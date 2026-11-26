package dev.tunssh.android.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.UploadFile
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import dev.tunssh.android.model.AuthType
import dev.tunssh.android.model.Profile
import dev.tunssh.android.ui.theme.TunSshColors

private val QUICK_PORTS = listOf(22, 443, 2053, 8443)

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ProfileDialog(
    profile: Profile?,
    pickedPrivateKey: String?,
    onConsumePickedPrivateKey: () -> Unit,
    onRequestPickPemFile: () -> Unit,
    onClearHostKey: (String) -> Unit,
    onDismiss: () -> Unit,
    onSave: (
        existingId: String?,
        name: String,
        host: String,
        port: Int,
        username: String,
        authType: String,
        password: String,
        privateKey: String,
        keyPassphrase: String,
        bypassIranLan: Boolean,
    ) -> Unit,
) {
    val isEditing = profile != null

    var name by remember(profile?.id) { mutableStateOf(profile?.name.orEmpty()) }
    var host by remember(profile?.id) { mutableStateOf(profile?.host.orEmpty()) }
    var portText by remember(profile?.id) { mutableStateOf((profile?.port ?: 22).toString()) }
    var username by remember(profile?.id) { mutableStateOf(profile?.username ?: "root") }
    var authType by remember(profile?.id) { mutableStateOf(profile?.authType ?: AuthType.PASSWORD) }
    var password by remember(profile?.id) { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    var privateKey by remember(profile?.id) { mutableStateOf("") }
    var keyPassphrase by remember(profile?.id) { mutableStateOf("") }
    var showPassphrase by remember { mutableStateOf(false) }
    var bypassIranLan by remember(profile?.id) { mutableStateOf(profile?.bypassIranLan ?: true) }
    var errorText by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(pickedPrivateKey) {
        if (!pickedPrivateKey.isNullOrBlank()) {
            authType = AuthType.KEY
            privateKey = pickedPrivateKey
            onConsumePickedPrivateKey()
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = TunSshColors.BgSurface,
        title = {
            Text(
                text = if (isEditing) "Edit Server Profile" else "New Server Profile",
                color = TunSshColors.TextPrimary,
            )
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Profile Name") },
                    placeholder = { Text("e.g. Germany VPS") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )

                OutlinedTextField(
                    value = host,
                    onValueChange = {
                        host = it
                        errorText = null
                    },
                    label = { Text("Server Host or IP") },
                    placeholder = { Text("vpn.example.com") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )

                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    OutlinedTextField(
                        value = portText,
                        onValueChange = { next ->
                            if (next.length <= 5 && next.all { it.isDigit() }) {
                                portText = next
                                errorText = null
                            }
                        },
                        label = { Text("SSH Port") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth(),
                    )

                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        QUICK_PORTS.forEach { qp ->
                            val selected = portText == qp.toString()
                            FilterChip(
                                selected = selected,
                                onClick = { portText = qp.toString() },
                                label = { Text(":$qp") },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = TunSshColors.AccentBlue.copy(alpha = 0.2f),
                                    selectedLabelColor = TunSshColors.AccentBlue,
                                ),
                            )
                        }
                    }
                }

                OutlinedTextField(
                    value = username,
                    onValueChange = {
                        username = it
                        errorText = null
                    },
                    label = { Text("Username") },
                    placeholder = { Text("root") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )

                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        text = "Authentication",
                        style = MaterialTheme.typography.labelMedium,
                        color = TunSshColors.TextMuted,
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        FilterChip(
                            selected = authType == AuthType.PASSWORD,
                            onClick = { authType = AuthType.PASSWORD },
                            leadingIcon = {
                                Icon(
                                    imageVector = Icons.Rounded.Lock,
                                    contentDescription = null,
                                    modifier = Modifier.size(16.dp),
                                )
                            },
                            label = { Text("Password") },
                            modifier = Modifier.weight(1f),
                        )
                        FilterChip(
                            selected = authType == AuthType.KEY,
                            onClick = { authType = AuthType.KEY },
                            leadingIcon = {
                                Icon(
                                    imageVector = Icons.Rounded.Key,
                                    contentDescription = null,
                                    modifier = Modifier.size(16.dp),
                                )
                            },
                            label = { Text("Private Key") },
                            modifier = Modifier.weight(1f),
                        )
                    }
                }

                if (authType == AuthType.PASSWORD) {
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it },
                        label = { Text("SSH Password") },
                        placeholder = {
                            Text(
                                if (isEditing) "Leave blank to keep saved password" else "Enter password",
                            )
                        },
                        singleLine = true,
                        visualTransformation = if (showPassword) {
                            VisualTransformation.None
                        } else {
                            PasswordVisualTransformation()
                        },
                        trailingIcon = {
                            IconButton(onClick = { showPassword = !showPassword }) {
                                Icon(
                                    imageVector = if (showPassword) {
                                        Icons.Rounded.VisibilityOff
                                    } else {
                                        Icons.Rounded.Visibility
                                    },
                                    contentDescription = "Toggle password visibility",
                                )
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                    )
                } else {
                    OutlinedButton(
                        onClick = onRequestPickPemFile,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.UploadFile,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Import .pem / OpenSSH Key File")
                    }

                    OutlinedTextField(
                        value = privateKey,
                        onValueChange = { privateKey = it },
                        label = { Text("Private Key (PEM / OpenSSH)") },
                        placeholder = {
                            Text(
                                if (isEditing && profile?.authType == AuthType.KEY) {
                                    "Leave blank to keep saved private key"
                                } else {
                                    "-----BEGIN OPENSSH PRIVATE KEY-----"
                                },
                            )
                        },
                        minLines = 3,
                        maxLines = 5,
                        textStyle = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace,
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    )

                    OutlinedTextField(
                        value = keyPassphrase,
                        onValueChange = { keyPassphrase = it },
                        label = { Text("Key Passphrase (Optional)") },
                        placeholder = {
                            Text(
                                if (isEditing && profile?.authType == AuthType.KEY) {
                                    "Leave blank to keep existing passphrase"
                                } else {
                                    "Empty if key is unencrypted"
                                },
                            )
                        },
                        singleLine = true,
                        visualTransformation = if (showPassphrase) {
                            VisualTransformation.None
                        } else {
                            PasswordVisualTransformation()
                        },
                        trailingIcon = {
                            IconButton(onClick = { showPassphrase = !showPassphrase }) {
                                Icon(
                                    imageVector = if (showPassphrase) {
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
                }

                Surface(
                    color = TunSshColors.BgInset,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Bypass Iran & LAN",
                                style = MaterialTheme.typography.bodyMedium,
                                color = TunSshColors.TextPrimary,
                            )
                            Text(
                                text = "Keep domestic Iranian sites & local network direct",
                                style = MaterialTheme.typography.bodySmall,
                                color = TunSshColors.TextMuted,
                            )
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Switch(
                            checked = bypassIranLan,
                            onCheckedChange = { bypassIranLan = it },
                        )
                    }
                }

                if (profile?.pinnedHostKey != null) {
                    Surface(
                        color = TunSshColors.BgInset,
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Row(
                                modifier = Modifier.weight(1f),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Icon(
                                    imageVector = Icons.Rounded.VerifiedUser,
                                    contentDescription = null,
                                    tint = TunSshColors.ConnectedGreen,
                                    modifier = Modifier.size(18.dp),
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Column {
                                    Text(
                                        text = "Pinned Host Key (${profile.pinnedHostKey.algorithm})",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = TunSshColors.TextPrimary,
                                    )
                                    Text(
                                        text = profile.pinnedHostKey.sha256,
                                        style = MaterialTheme.typography.bodySmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                        ),
                                        color = TunSshColors.TextMuted,
                                        maxLines = 1,
                                    )
                                }
                            }
                            TextButton(onClick = { onClearHostKey(profile.id) }) {
                                Text("Clear", color = TunSshColors.WarningAmber)
                            }
                        }
                    }
                }

                if (errorText != null) {
                    Text(
                        text = errorText!!,
                        style = MaterialTheme.typography.bodySmall,
                        color = TunSshColors.ErrorRed,
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val trimmedHost = host.trim()
                    val trimmedUser = username.trim()
                    val parsedPort = portText.toIntOrNull()
                    when {
                        trimmedHost.isEmpty() -> errorText = "Server host is required."
                        parsedPort == null || parsedPort !in 1..65535 -> {
                            errorText = "Port must be between 1 and 65535."
                        }
                        trimmedUser.isEmpty() -> errorText = "Username is required."
                        authType == AuthType.KEY &&
                            privateKey.isBlank() &&
                            (!isEditing || profile?.authType != AuthType.KEY) -> {
                            errorText = "Paste or import a PEM/OpenSSH private key."
                        }
                        else -> {
                            onSave(
                                profile?.id,
                                name.trim().ifBlank { "$trimmedHost:$parsedPort" },
                                trimmedHost,
                                parsedPort,
                                trimmedUser,
                                authType,
                                password,
                                privateKey,
                                keyPassphrase,
                                bypassIranLan,
                            )
                        }
                    }
                },
                colors = ButtonDefaults.buttonColors(containerColor = TunSshColors.AccentBlue),
            ) {
                Text(if (isEditing) "Save" else "Create")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel", color = TunSshColors.TextMuted)
            }
        },
    )
}
