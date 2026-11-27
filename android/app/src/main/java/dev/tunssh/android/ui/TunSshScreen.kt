package dev.tunssh.android.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.ArrowDownward
import androidx.compose.material.icons.rounded.ArrowUpward
import androidx.compose.material.icons.rounded.BatteryAlert
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.KeyboardArrowDown
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material.icons.rounded.Timer
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.tunssh.android.model.AppSettings
import dev.tunssh.android.model.ErrorDTO
import dev.tunssh.android.model.Profile
import dev.tunssh.android.model.StatusDTO
import dev.tunssh.android.model.TunnelState
import dev.tunssh.android.ui.components.AppBypassDialog
import dev.tunssh.android.ui.components.HostKeyDialog
import dev.tunssh.android.ui.components.LogSheet
import dev.tunssh.android.ui.components.ProfileDialog
import dev.tunssh.android.ui.components.QrScannerDialog
import dev.tunssh.android.ui.components.ShareDialog
import dev.tunssh.android.ui.theme.TunSshColors
import kotlinx.coroutines.delay

private val PROFILE_FIXABLE_ERROR_CODES = setOf(
    "ERR_PORT22_TIMEOUT",
    "ERR_DPI_RESET",
    "ERR_CONN_REFUSED",
    "ERR_AUTH_FAILED",
    "ERR_KEY_INVALID",
)

@Composable
fun TunSshScreen(
    viewModel: MainViewModel,
    isIgnoringBatteryOptimizations: Boolean,
    pickedPrivateKey: String?,
    onConsumePickedPrivateKey: () -> Unit,
    showQrScanner: Boolean,
    pickedQrLink: String?,
    onConsumePickedQrLink: () -> Unit,
    onRequestScanQrCamera: () -> Unit,
    onRequestPickQrImage: () -> Unit,
    onQrScannedFromCamera: (String) -> Unit,
    onDismissQrScanner: () -> Unit,
    onRequestConnectWithPermissions: (profileId: String) -> Unit,
    onRequestPickPemFile: () -> Unit,
    onRequestIgnoreBatteryOptimizations: () -> Unit,
    onShareViaSystemSheet: (String) -> Unit,
) {
    val profiles by viewModel.profiles.collectAsState()
    val settings by viewModel.settings.collectAsState()
    val status by viewModel.status.collectAsState()
    val hostKeyPrompt by viewModel.hostKeyPrompt.collectAsState()
    val logs by viewModel.logs.collectAsState()
    val unreadAlertCount by viewModel.unreadAlertCount.collectAsState()
    val pendingDeepLink by viewModel.pendingDeepLink.collectAsState()
    val toastMessage by viewModel.toastMessage.collectAsState()

    val snackbarHostState = remember { SnackbarHostState() }

    var isCreatingProfile by remember { mutableStateOf(false) }
    var editingProfileId by remember { mutableStateOf<String?>(null) }
    var shareDialogState by remember { mutableStateOf<Pair<Boolean, String?>>(false to null) }
    var shareSelectedProfileId by remember { mutableStateOf<String?>(null) }
    var scannedShareUri by remember { mutableStateOf<String?>(null) }
    var appBypassOpen by remember { mutableStateOf(false) }
    var logsSheetOpen by remember { mutableStateOf(false) }

    val editingProfile = remember(profiles, editingProfileId) {
        editingProfileId?.let { id -> profiles.firstOrNull { it.id == id } }
    }

    LaunchedEffect(toastMessage) {
        val msg = toastMessage ?: return@LaunchedEffect
        snackbarHostState.showSnackbar(msg)
        viewModel.consumeToast()
    }

    LaunchedEffect(pendingDeepLink) {
        val link = pendingDeepLink ?: return@LaunchedEffect
        shareSelectedProfileId = settings.selectedProfileId
        shareDialogState = true to link
        viewModel.consumeDeepLink()
    }

    LaunchedEffect(pickedQrLink) {
        val link = pickedQrLink ?: return@LaunchedEffect
        scannedShareUri = link
        if (!shareDialogState.first) {
            shareSelectedProfileId = settings.selectedProfileId
            shareDialogState = true to link
        }
        onConsumePickedQrLink()
    }

    val activeProfile = remember(profiles, settings.selectedProfileId, status.profileId, status.state) {
        val statusId = status.profileId
        if (TunnelState.isActive(status.state) && statusId.isNotBlank()) {
            profiles.firstOrNull { it.id == statusId }
        } else {
            null
        } ?: profiles.firstOrNull { it.id == settings.selectedProfileId } ?: profiles.firstOrNull()
    }

    val isTunnelActive = TunnelState.isActive(status.state)

    Scaffold(
        containerColor = TunSshColors.BgCanvas,
        snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
        topBar = {
            TopHeaderBar(
                profiles = profiles,
                activeProfile = activeProfile,
                isTunnelActive = isTunnelActive,
                unreadAlertCount = unreadAlertCount,
                onSelectProfile = { viewModel.selectProfile(it) },
                onAddProfile = {
                    editingProfileId = null
                    isCreatingProfile = true
                },
                onOpenShare = {
                    shareSelectedProfileId = activeProfile?.id
                    shareDialogState = true to null
                },
                onOpenLogs = {
                    viewModel.markLogsOpened()
                    logsSheetOpen = true
                },
            )
        },
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (!isIgnoringBatteryOptimizations && !settings.batteryBannerDismissed) {
                item(key = "battery_banner") {
                    BatteryOptimizationBanner(
                        onAllow = onRequestIgnoreBatteryOptimizations,
                        onDismiss = { viewModel.dismissBatteryBanner() },
                    )
                }
            }

            status.lastError?.let { error ->
                item(key = "error_card") {
                    ErrorDiagnosticCard(
                        error = error,
                        canEditProfile = activeProfile != null && error.code in PROFILE_FIXABLE_ERROR_CODES,
                        onEditProfile = {
                            if (activeProfile != null) {
                                isCreatingProfile = false
                                editingProfileId = activeProfile.id
                            }
                        },
                    )
                }
            }

            item(key = "hero_card") {
                HeroConnectionCard(
                    status = status,
                    activeProfile = activeProfile,
                    onConnect = {
                        if (activeProfile == null) {
                            editingProfileId = null
                            isCreatingProfile = true
                        } else {
                            onRequestConnectWithPermissions(activeProfile.id)
                        }
                    },
                    onDisconnect = { viewModel.disconnect() },
                )
            }

            item(key = "routing_card") {
                ModeRoutingCard(
                    activeProfile = activeProfile,
                    settings = settings,
                    isTunnelActive = isTunnelActive,
                    onToggleBypass = { bypass ->
                        activeProfile?.let { viewModel.toggleBypass(it.id, bypass) }
                    },
                    onToggleIpv6 = { enabled -> viewModel.setEnableIpv6(enabled) },
                    onOpenSplitTunneling = { appBypassOpen = true },
                )
            }

            item(key = "profiles_header") {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = "Server Profiles (${profiles.size})",
                        style = MaterialTheme.typography.titleMedium,
                        color = TunSshColors.TextPrimary,
                    )
                    TextButton(
                        onClick = {
                            editingProfileId = null
                            isCreatingProfile = true
                        },
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Add,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Add Profile")
                    }
                }
            }

            if (profiles.isEmpty()) {
                item(key = "empty_profiles") {
                    Surface(
                        color = TunSshColors.BgSurface,
                        shape = RoundedCornerShape(14.dp),
                        border = BorderStroke(1.dp, TunSshColors.BorderSubtle),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(
                            modifier = Modifier.padding(20.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Text(
                                text = "No SSH profiles yet",
                                style = MaterialTheme.typography.titleMedium,
                                color = TunSshColors.TextPrimary,
                            )
                            Text(
                                text = "Add your VPS details or import an sshtun://v1/ share link to start tunneling.",
                                style = MaterialTheme.typography.bodySmall,
                                color = TunSshColors.TextMuted,
                            )
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(
                                    onClick = {
                                        editingProfileId = null
                                        isCreatingProfile = true
                                    },
                                    colors = ButtonDefaults.buttonColors(containerColor = TunSshColors.AccentBlue),
                                ) {
                                    Text("Create Profile")
                                }
                                OutlinedButton(
                                    onClick = {
                                        shareSelectedProfileId = null
                                        shareDialogState = true to null
                                    },
                                ) {
                                    Text("Import Link")
                                }
                            }
                        }
                    }
                }
            } else {
                items(profiles, key = { it.id }) { profile ->
                    val isSelected = profile.id == activeProfile?.id
                    val isLockedByActiveTunnel = isTunnelActive && isSelected
                    ProfileListCard(
                        profile = profile,
                        isSelected = isSelected,
                        isLockedByActiveTunnel = isLockedByActiveTunnel,
                        selectionLocked = isTunnelActive,
                        onSelect = { viewModel.selectProfile(profile.id) },
                        onEdit = {
                            isCreatingProfile = false
                            editingProfileId = profile.id
                        },
                        onShare = {
                            shareSelectedProfileId = profile.id
                            shareDialogState = true to null
                        },
                        onDelete = { viewModel.deleteProfile(profile.id) },
                    )
                }
            }

            item { Spacer(modifier = Modifier.height(16.dp)) }
        }
    }

    if (isCreatingProfile || editingProfile != null) {
        ProfileDialog(
            profile = editingProfile,
            pickedPrivateKey = pickedPrivateKey,
            onConsumePickedPrivateKey = onConsumePickedPrivateKey,
            onRequestPickPemFile = onRequestPickPemFile,
            onClearHostKey = { profileId -> viewModel.clearHostKey(profileId) },
            onDismiss = {
                isCreatingProfile = false
                editingProfileId = null
            },
            onSave = { existingId, name, host, port, username, authType, password, privateKey, keyPassphrase, bypassIranLan ->
                viewModel.saveProfile(
                    existingId = existingId,
                    name = name,
                    host = host,
                    port = port,
                    username = username,
                    authType = authType,
                    password = password,
                    privateKey = privateKey,
                    keyPassphrase = keyPassphrase,
                    bypassIranLan = bypassIranLan,
                ) {
                    isCreatingProfile = false
                    editingProfileId = null
                }
            },
        )
    }

    hostKeyPrompt?.let { prompt ->
        HostKeyDialog(
            prompt = prompt,
            onTrustAndConnect = { viewModel.trustHostKeyAndConnect(it) },
            onForgetAndReconnect = { viewModel.forgetAndReconnect(it) },
            onCancel = { viewModel.cancelHostKeyPrompt() },
            onCopied = { viewModel.showToast("Fingerprint copied") },
        )
    }

    if (shareDialogState.first) {
        ShareDialog(
            profiles = profiles,
            activeProfileId = shareSelectedProfileId ?: activeProfile?.id,
            initialImportUri = shareDialogState.second,
            scannedUri = scannedShareUri,
            onConsumeScannedUri = { scannedShareUri = null },
            onRequestScanQrCamera = onRequestScanQrCamera,
            onRequestPickQrImage = onRequestPickQrImage,
            onInspect = { link -> viewModel.inspectShareLink(link) },
            onExport = { id, pass, plain -> viewModel.exportShareLink(id, pass, plain) },
            onImport = { link, pass, plain -> viewModel.importShareLink(link, pass, plain) },
            onShareViaSystemSheet = onShareViaSystemSheet,
            onCopied = { msg -> viewModel.showToast(msg) },
            onDismiss = {
                scannedShareUri = null
                shareDialogState = false to null
            },
        )
    }

    if (showQrScanner) {
        QrScannerDialog(
            onQrScanned = onQrScannedFromCamera,
            onDismiss = onDismissQrScanner,
        )
    }

    if (appBypassOpen) {
        AppBypassDialog(
            initialExcludedPackages = settings.disallowedPackages,
            onSave = { selected ->
                viewModel.setDisallowedPackages(selected)
                appBypassOpen = false
            },
            onDismiss = { appBypassOpen = false },
        )
    }

    if (logsSheetOpen) {
        LogSheet(
            logs = logs,
            onExportText = { viewModel.exportRedactedLogsText() },
            onClear = { viewModel.clearLogs() },
            onCopied = { viewModel.showToast("Redacted logs copied") },
            onDismiss = { logsSheetOpen = false },
        )
    }
}

@Composable
private fun TopHeaderBar(
    profiles: List<Profile>,
    activeProfile: Profile?,
    isTunnelActive: Boolean,
    unreadAlertCount: Int,
    onSelectProfile: (String) -> Unit,
    onAddProfile: () -> Unit,
    onOpenShare: () -> Unit,
    onOpenLogs: () -> Unit,
) {
    var selectorExpanded by remember { mutableStateOf(false) }

    Surface(
        color = TunSshColors.BgCanvas,
        tonalElevation = 0.dp,
    ) {
        Column(modifier = Modifier.statusBarsPadding()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.weight(1f),
                ) {
                    Surface(
                        color = TunSshColors.AccentBlue.copy(alpha = 0.14f),
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, TunSshColors.AccentBlue.copy(alpha = 0.4f)),
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Shield,
                            contentDescription = "tunssh",
                            tint = TunSshColors.AccentBlue,
                            modifier = Modifier
                                .padding(7.dp)
                                .size(20.dp),
                        )
                    }
                    Text(
                        text = "tunssh",
                        style = MaterialTheme.typography.titleLarge,
                        color = TunSshColors.TextPrimary,
                    )

                    Spacer(modifier = Modifier.width(4.dp))

                    Box {
                        Surface(
                            color = TunSshColors.BgSurface,
                            shape = RoundedCornerShape(20.dp),
                            border = BorderStroke(1.dp, TunSshColors.BorderSubtle),
                            modifier = Modifier
                                .clip(RoundedCornerShape(20.dp))
                                .clickable(enabled = !isTunnelActive) { selectorExpanded = true },
                        ) {
                            Row(
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(
                                    text = activeProfile?.name ?: "No profile",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = if (isTunnelActive) {
                                        TunSshColors.TextMuted
                                    } else {
                                        TunSshColors.TextPrimary
                                    },
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                                Spacer(modifier = Modifier.width(2.dp))
                                Icon(
                                    imageVector = Icons.Rounded.KeyboardArrowDown,
                                    contentDescription = "Switch profile",
                                    tint = TunSshColors.TextMuted,
                                    modifier = Modifier.size(16.dp),
                                )
                            }
                        }

                        DropdownMenu(
                            expanded = selectorExpanded,
                            onDismissRequest = { selectorExpanded = false },
                            containerColor = TunSshColors.BgElevated,
                        ) {
                            profiles.forEach { profile ->
                                DropdownMenuItem(
                                    text = {
                                        Text("${profile.name} (${profile.host}:${profile.port})")
                                    },
                                    onClick = {
                                        onSelectProfile(profile.id)
                                        selectorExpanded = false
                                    },
                                )
                            }
                            if (profiles.isNotEmpty()) {
                                HorizontalDivider(color = TunSshColors.BorderSubtle)
                            }
                            DropdownMenuItem(
                                text = { Text("+ New Profile", color = TunSshColors.AccentBlue) },
                                onClick = {
                                    selectorExpanded = false
                                    onAddProfile()
                                },
                            )
                        }
                    }
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = onOpenShare) {
                        Icon(
                            imageVector = Icons.Rounded.Share,
                            contentDescription = "Share or import profile",
                            tint = TunSshColors.TextMuted,
                        )
                    }
                    IconButton(onClick = onOpenLogs) {
                        BadgedBox(
                            badge = {
                                if (unreadAlertCount > 0) {
                                    Badge(containerColor = TunSshColors.ErrorRed) {
                                        Text(
                                            text = if (unreadAlertCount > 99) "99+" else "$unreadAlertCount",
                                            color = Color.White,
                                        )
                                    }
                                }
                            },
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.Terminal,
                                contentDescription = "Diagnostic logs",
                                tint = TunSshColors.TextMuted,
                            )
                        }
                    }
                }
            }
            HorizontalDivider(color = TunSshColors.BorderSubtle)
        }
    }
}

@Composable
private fun BatteryOptimizationBanner(
    onAllow: () -> Unit,
    onDismiss: () -> Unit,
) {
    Surface(
        color = TunSshColors.WarningAmber.copy(alpha = 0.1f),
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(1.dp, TunSshColors.WarningAmber.copy(alpha = 0.4f)),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(
                    imageVector = Icons.Rounded.BatteryAlert,
                    contentDescription = null,
                    tint = TunSshColors.WarningAmber,
                    modifier = Modifier.size(20.dp),
                )
                Text(
                    text = "Keep Tunnel Alive in Background",
                    style = MaterialTheme.typography.titleMedium,
                    color = TunSshColors.WarningAmber,
                )
            }
            Text(
                text = "Allow unrestricted battery usage so Android Doze does not suspend your SSH tunnel while the screen is off.",
                style = MaterialTheme.typography.bodySmall,
                color = TunSshColors.TextMuted,
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
            ) {
                TextButton(onClick = onDismiss) {
                    Text("Dismiss", color = TunSshColors.TextMuted)
                }
                Spacer(modifier = Modifier.width(8.dp))
                Button(
                    onClick = onAllow,
                    colors = ButtonDefaults.buttonColors(containerColor = TunSshColors.WarningAmber),
                ) {
                    Text("Allow Unrestricted", color = TunSshColors.BgCanvas)
                }
            }
        }
    }
}

@Composable
private fun ErrorDiagnosticCard(
    error: ErrorDTO,
    canEditProfile: Boolean,
    onEditProfile: () -> Unit,
) {
    Surface(
        color = TunSshColors.ErrorRed.copy(alpha = 0.1f),
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(1.dp, TunSshColors.ErrorRed.copy(alpha = 0.45f)),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(
                    imageVector = Icons.Rounded.Warning,
                    contentDescription = null,
                    tint = TunSshColors.ErrorRed,
                    modifier = Modifier.size(18.dp),
                )
                Surface(
                    color = TunSshColors.ErrorRed.copy(alpha = 0.2f),
                    shape = RoundedCornerShape(6.dp),
                ) {
                    Text(
                        text = error.code.ifBlank { "ERR_TUNNEL" },
                        style = MaterialTheme.typography.labelMedium.copy(fontFamily = FontFamily.Monospace),
                        color = TunSshColors.ErrorRed,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                    )
                }
            }
            Text(
                text = error.message,
                style = MaterialTheme.typography.bodyMedium,
                color = TunSshColors.TextPrimary,
            )
            if (error.actionHint.isNotBlank()) {
                Text(
                    text = error.actionHint,
                    style = MaterialTheme.typography.bodySmall,
                    color = TunSshColors.TextMuted,
                )
            }
            if (canEditProfile) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                ) {
                    OutlinedButton(onClick = onEditProfile) {
                        Text("Edit Profile")
                    }
                }
            }
        }
    }
}

@Composable
private fun HeroConnectionCard(
    status: StatusDTO,
    activeProfile: Profile?,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    var elapsedSeconds by remember { mutableLongStateOf(0L) }
    LaunchedEffect(status.state, status.connectedAtUnix) {
        if (status.state != TunnelState.CONNECTED || status.connectedAtUnix <= 0L) {
            elapsedSeconds = 0L
            return@LaunchedEffect
        }
        while (true) {
            val nowSec = System.currentTimeMillis() / 1000L
            elapsedSeconds = (nowSec - status.connectedAtUnix).coerceAtLeast(0L)
            delay(1000L)
        }
    }

    val isConnected = status.state == TunnelState.CONNECTED
    val isTransitioning = status.state == TunnelState.CONNECTING || status.state == TunnelState.RECONNECTING
    val isError = status.state == TunnelState.ERROR

    val statusColor = when {
        isConnected -> TunSshColors.ConnectedGreen
        isTransitioning -> TunSshColors.WarningAmber
        isError -> TunSshColors.ErrorRed
        else -> TunSshColors.DisconnectedSlate
    }

    val statusLabel = when (status.state) {
        TunnelState.CONNECTED -> if (status.tunAttached) "Connected • TUN" else "Connected"
        TunnelState.CONNECTING -> "Connecting..."
        TunnelState.RECONNECTING -> "Reconnecting (attempt #${status.attempt.coerceAtLeast(1)})..."
        TunnelState.ERROR -> "Action Required"
        else -> "Disconnected"
    }

    val pulseAlpha = if (isTransitioning) {
        val transition = rememberInfiniteTransition(label = "pulse")
        val alpha by transition.animateFloat(
            initialValue = 1f,
            targetValue = 0.3f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 700),
                repeatMode = RepeatMode.Reverse,
            ),
            label = "dot_alpha",
        )
        alpha
    } else {
        1f
    }

    val buttonColor by animateColorAsState(
        targetValue = when {
            isConnected -> TunSshColors.ErrorRed
            isTransitioning -> TunSshColors.WarningAmber
            else -> TunSshColors.AccentBlue
        },
        label = "connect_btn_color",
    )

    val buttonLabel = when {
        activeProfile == null -> "Create First Profile"
        isConnected -> "Disconnect"
        status.state == TunnelState.CONNECTING -> "Cancel Connection"
        status.state == TunnelState.RECONNECTING -> "Cancel Reconnect"
        else -> "Connect"
    }

    Surface(
        color = TunSshColors.BgSurface,
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, TunSshColors.BorderSubtle),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Surface(
                    color = statusColor.copy(alpha = 0.14f),
                    shape = RoundedCornerShape(20.dp),
                    border = BorderStroke(1.dp, statusColor.copy(alpha = 0.45f)),
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Box(
                            modifier = Modifier
                                .size(8.dp)
                                .alpha(pulseAlpha)
                                .clip(CircleShape)
                                .background(statusColor),
                        )
                        Text(
                            text = statusLabel,
                            style = MaterialTheme.typography.labelMedium,
                            color = statusColor,
                        )
                    }
                }

                Text(
                    text = FormatUtils.formatDuration(elapsedSeconds),
                    style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                    color = if (isConnected) TunSshColors.TextPrimary else TunSshColors.TextSubtle,
                )
            }

            if (activeProfile != null) {
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        text = activeProfile.name,
                        style = MaterialTheme.typography.titleMedium,
                        color = TunSshColors.TextPrimary,
                    )
                    Text(
                        text = "${activeProfile.username}@${activeProfile.host}:${activeProfile.port}",
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        color = TunSshColors.TextMuted,
                    )
                }
            }

            Button(
                onClick = {
                    if (isConnected || isTransitioning) {
                        onDisconnect()
                    } else {
                        onConnect()
                    }
                },
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = buttonColor),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp),
            ) {
                Icon(
                    imageVector = Icons.Rounded.PowerSettingsNew,
                    contentDescription = null,
                    tint = if (isTransitioning) TunSshColors.BgCanvas else Color.White,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = buttonLabel,
                    fontWeight = FontWeight.SemiBold,
                    color = if (isTransitioning) TunSshColors.BgCanvas else Color.White,
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                TelemetryTile(
                    icon = Icons.Rounded.Speed,
                    label = "RTT",
                    value = if (isConnected && status.rttMs > 0) "${status.rttMs} ms" else "—",
                    subValue = "SSH ping",
                    modifier = Modifier.weight(1f),
                )
                TelemetryTile(
                    icon = Icons.Rounded.Timer,
                    label = "Uptime",
                    value = if (isConnected) FormatUtils.formatDuration(elapsedSeconds) else "—",
                    subValue = if (status.tunAttached) "TUN up" else "Standby",
                    modifier = Modifier.weight(1f),
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                TelemetryTile(
                    icon = Icons.Rounded.ArrowDownward,
                    label = "Download",
                    value = FormatUtils.formatBytes(status.rxBytes),
                    subValue = FormatUtils.formatRate(status.rxRateBps),
                    modifier = Modifier.weight(1f),
                )
                TelemetryTile(
                    icon = Icons.Rounded.ArrowUpward,
                    label = "Upload",
                    value = FormatUtils.formatBytes(status.txBytes),
                    subValue = FormatUtils.formatRate(status.txRateBps),
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }
}

@Composable
private fun TelemetryTile(
    icon: ImageVector,
    label: String,
    value: String,
    subValue: String,
    modifier: Modifier = Modifier,
) {
    Surface(
        color = TunSshColors.BgInset,
        shape = RoundedCornerShape(10.dp),
        border = BorderStroke(1.dp, TunSshColors.BorderSubtle),
        modifier = modifier,
    ) {
        Column(
            modifier = Modifier.padding(10.dp),
            verticalArrangement = Arrangement.spacedBy(3.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = TunSshColors.TextSubtle,
                    modifier = Modifier.size(14.dp),
                )
                Text(
                    text = label,
                    style = MaterialTheme.typography.bodySmall,
                    color = TunSshColors.TextMuted,
                )
            }
            Text(
                text = value,
                style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace),
                color = TunSshColors.TextPrimary,
            )
            Text(
                text = subValue,
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                color = TunSshColors.TextSubtle,
            )
        }
    }
}

@Composable
private fun ModeRoutingCard(
    activeProfile: Profile?,
    settings: AppSettings,
    isTunnelActive: Boolean,
    onToggleBypass: (Boolean) -> Unit,
    onToggleIpv6: (Boolean) -> Unit,
    onOpenSplitTunneling: () -> Unit,
) {
    Surface(
        color = TunSshColors.BgSurface,
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, TunSshColors.BorderSubtle),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                text = "Routing & Leak Protection",
                style = MaterialTheme.typography.titleMedium,
                color = TunSshColors.TextPrimary,
            )
            Spacer(modifier = Modifier.height(10.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
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
                        text = "Route Iranian & local subnets directly (live toggle)",
                        style = MaterialTheme.typography.bodySmall,
                        color = TunSshColors.TextMuted,
                    )
                }
                Spacer(modifier = Modifier.width(8.dp))
                Switch(
                    checked = activeProfile?.bypassIranLan ?: true,
                    enabled = activeProfile != null,
                    onCheckedChange = onToggleBypass,
                )
            }

            HorizontalDivider(
                modifier = Modifier.padding(vertical = 10.dp),
                color = TunSshColors.BorderSubtle,
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "IPv6 Leak Prevention",
                        style = MaterialTheme.typography.bodyMedium,
                        color = TunSshColors.TextPrimary,
                    )
                    Text(
                        text = if (isTunnelActive) {
                            "Disconnect to change IPv6 TUN routing"
                        } else {
                            "Capture IPv6 routes into TUN to prevent leaks"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = TunSshColors.TextMuted,
                    )
                }
                Spacer(modifier = Modifier.width(8.dp))
                Switch(
                    checked = settings.enableIpv6,
                    enabled = !isTunnelActive,
                    onCheckedChange = onToggleIpv6,
                )
            }

            HorizontalDivider(
                modifier = Modifier.padding(vertical = 10.dp),
                color = TunSshColors.BorderSubtle,
            )

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .clickable(onClick = onOpenSplitTunneling)
                    .padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Apps,
                        contentDescription = null,
                        tint = TunSshColors.AccentBlue,
                        modifier = Modifier.size(20.dp),
                    )
                    Column {
                        Text(
                            text = "Per-App Split Tunneling",
                            style = MaterialTheme.typography.bodyMedium,
                            color = TunSshColors.TextPrimary,
                        )
                        Text(
                            text = "${settings.disallowedPackages.size} apps excluded (banking / domestic)",
                            style = MaterialTheme.typography.bodySmall,
                            color = TunSshColors.TextMuted,
                        )
                    }
                }
                Text(
                    text = "Configure",
                    style = MaterialTheme.typography.labelMedium,
                    color = TunSshColors.AccentBlue,
                )
            }
        }
    }
}

@Composable
private fun ProfileListCard(
    profile: Profile,
    isSelected: Boolean,
    isLockedByActiveTunnel: Boolean,
    selectionLocked: Boolean,
    onSelect: () -> Unit,
    onEdit: () -> Unit,
    onShare: () -> Unit,
    onDelete: () -> Unit,
) {
    val borderColor = if (isSelected) {
        TunSshColors.AccentBlue.copy(alpha = 0.65f)
    } else {
        TunSshColors.BorderSubtle
    }

    Surface(
        color = TunSshColors.BgSurface,
        shape = RoundedCornerShape(14.dp),
        border = BorderStroke(1.dp, borderColor),
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .clickable(enabled = !selectionLocked) { onSelect() },
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            RadioButton(
                selected = isSelected,
                enabled = !selectionLocked,
                onClick = onSelect,
            )
            Column(modifier = Modifier.weight(1f)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        text = profile.name,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                        color = TunSshColors.TextPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    if (profile.pinnedHostKey != null) {
                        Icon(
                            imageVector = Icons.Rounded.VerifiedUser,
                            contentDescription = "Host key pinned",
                            tint = TunSshColors.ConnectedGreen,
                            modifier = Modifier.size(15.dp),
                        )
                    }
                }
                Text(
                    text = "${profile.username}@${profile.host}:${profile.port} • ${profile.authType}",
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    color = TunSshColors.TextMuted,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            IconButton(onClick = onShare) {
                Icon(
                    imageVector = Icons.Rounded.Share,
                    contentDescription = "Share profile",
                    tint = TunSshColors.TextMuted,
                    modifier = Modifier.size(18.dp),
                )
            }
            IconButton(
                onClick = onEdit,
                enabled = !isLockedByActiveTunnel,
            ) {
                Icon(
                    imageVector = Icons.Rounded.Edit,
                    contentDescription = "Edit profile",
                    tint = if (isLockedByActiveTunnel) TunSshColors.TextSubtle else TunSshColors.TextMuted,
                    modifier = Modifier.size(18.dp),
                )
            }
            IconButton(
                onClick = onDelete,
                enabled = !isLockedByActiveTunnel,
            ) {
                Icon(
                    imageVector = Icons.Rounded.Delete,
                    contentDescription = "Delete profile",
                    tint = if (isLockedByActiveTunnel) TunSshColors.TextSubtle else TunSshColors.ErrorRed,
                    modifier = Modifier.size(18.dp),
                )
            }
        }
    }
}
