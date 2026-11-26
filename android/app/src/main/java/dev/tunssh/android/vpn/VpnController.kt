package dev.tunssh.android.vpn

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat
import dev.tunssh.android.model.HostKeyPromptDTO
import dev.tunssh.android.model.LogEntryDTO
import dev.tunssh.android.model.ShareLinkMetaDTO
import dev.tunssh.android.model.SharePayloadDTO
import dev.tunssh.android.model.StatusDTO
import dev.tunssh.android.model.TunnelState
import dev.tunssh.android.model.VPNPlanDTO
import dev.tunssh.mobile.Mobile
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * Process-wide reactive bridge between TunSshVpnService, MainViewModel, TunSshTileService,
 * and the gomobile Go core.
 */
object VpnController {

    private const val MAX_LOG_ENTRIES = 500

    private val _status = MutableStateFlow(StatusDTO())
    val status: StateFlow<StatusDTO> = _status.asStateFlow()

    private val _hostKeyPrompt = MutableStateFlow<HostKeyPromptDTO?>(null)
    val hostKeyPrompt: StateFlow<HostKeyPromptDTO?> = _hostKeyPrompt.asStateFlow()

    private val _logs = MutableStateFlow<List<LogEntryDTO>>(emptyList())
    val logs: StateFlow<List<LogEntryDTO>> = _logs.asStateFlow()

    private val _unreadAlertCount = MutableStateFlow(0)
    val unreadAlertCount: StateFlow<Int> = _unreadAlertCount.asStateFlow()

    private val _profileVersion = MutableStateFlow(0L)
    val profileVersion: StateFlow<Long> = _profileVersion.asStateFlow()

    fun connect(context: Context, profileId: String) {
        _hostKeyPrompt.value = null
        val intent = Intent(context, TunSshVpnService::class.java).apply {
            action = TunSshVpnService.ACTION_CONNECT
            putExtra(TunSshVpnService.EXTRA_PROFILE_ID, profileId)
        }
        ContextCompat.startForegroundService(context, intent)
    }

    fun disconnect(context: Context) {
        _hostKeyPrompt.value = null
        val intent = Intent(context, TunSshVpnService::class.java).apply {
            action = TunSshVpnService.ACTION_DISCONNECT
        }
        runCatching { context.startService(intent) }
    }

    fun toggleBypass(context: Context, bypassIranLan: Boolean) {
        if (!TunnelState.isActive(_status.value.state)) return
        val intent = Intent(context, TunSshVpnService::class.java).apply {
            action = TunSshVpnService.ACTION_TOGGLE_BYPASS
            putExtra(TunSshVpnService.EXTRA_BYPASS_IRAN_LAN, bypassIranLan)
        }
        runCatching { context.startService(intent) }
    }

    fun trustHostKeyAndConnect(
        context: Context,
        profileId: String,
        algorithm: String,
        sha256: String,
    ) {
        _hostKeyPrompt.value = null
        val intent = Intent(context, TunSshVpnService::class.java).apply {
            action = TunSshVpnService.ACTION_TRUST_HOSTKEY
            putExtra(TunSshVpnService.EXTRA_PROFILE_ID, profileId)
            putExtra(TunSshVpnService.EXTRA_HOSTKEY_ALG, algorithm)
            putExtra(TunSshVpnService.EXTRA_HOSTKEY_SHA256, sha256)
        }
        ContextCompat.startForegroundService(context, intent)
    }

    fun buildVpnPlan(bypassIranLan: Boolean, enableIpv6: Boolean, mtu: Int = 0): VPNPlanDTO {
        val json = Mobile.buildVpnPlan(bypassIranLan, enableIpv6, mtu)
        return VPNPlanDTO.fromJsonString(json)
    }

    fun inspectShareLink(link: String): ShareLinkMetaDTO {
        val json = Mobile.inspectShareLink(link)
        return ShareLinkMetaDTO.fromJsonString(json)
    }

    fun decodeShareLink(link: String, passphrase: String, allowPlain: Boolean): SharePayloadDTO {
        val json = Mobile.decodeShareLink(link, passphrase, allowPlain)
        return SharePayloadDTO.fromJsonString(json)
    }

    fun encodeShareLink(
        payload: SharePayloadDTO,
        passphrase: String,
        allowPlain: Boolean,
    ): String {
        return Mobile.encodeShareLink(payload.toJsonString(), passphrase, allowPlain)
    }

    fun clearHostKeyPrompt() {
        _hostKeyPrompt.value = null
    }

    fun markAlertsRead() {
        _unreadAlertCount.value = 0
    }

    fun clearLogs(context: Context? = null) {
        _logs.value = emptyList()
        _unreadAlertCount.value = 0
        if (context != null && TunnelState.isActive(_status.value.state)) {
            val intent = Intent(context, TunSshVpnService::class.java).apply {
                action = TunSshVpnService.ACTION_CLEAR_LOGS
            }
            runCatching { context.startService(intent) }
        }
    }

    internal fun onStatusFromEngine(next: StatusDTO) {
        _status.value = next
    }

    internal fun onHostKeyPromptFromEngine(prompt: HostKeyPromptDTO) {
        _hostKeyPrompt.value = prompt
    }

    internal fun onLogFromEngine(entry: LogEntryDTO) {
        _logs.update { current ->
            val updated = current + entry
            if (updated.size > MAX_LOG_ENTRIES) {
                updated.takeLast(MAX_LOG_ENTRIES)
            } else {
                updated
            }
        }
        if (entry.level == "WARN" || entry.level == "ERROR") {
            _unreadAlertCount.update { it + 1 }
        }
    }

    internal fun setLogsSnapshot(entries: List<LogEntryDTO>) {
        _logs.value = entries.takeLast(MAX_LOG_ENTRIES)
    }

    internal fun notifyProfilesChanged() {
        _profileVersion.update { it + 1L }
    }

    internal fun requestTileUpdate(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            runCatching {
                TileService.requestListeningState(
                    context.applicationContext,
                    ComponentName(context.applicationContext, TunSshTileService::class.java),
                )
            }
        }
    }
}
