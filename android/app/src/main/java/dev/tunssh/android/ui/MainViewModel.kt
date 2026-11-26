package dev.tunssh.android.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.tunssh.android.data.ProfileRepository
import dev.tunssh.android.model.AppSettings
import dev.tunssh.android.model.AuthType
import dev.tunssh.android.model.HostKeyPinDTO
import dev.tunssh.android.model.HostKeyPromptDTO
import dev.tunssh.android.model.LogEntryDTO
import dev.tunssh.android.model.Profile
import dev.tunssh.android.model.ProfileSecrets
import dev.tunssh.android.model.ShareHostKeyDTO
import dev.tunssh.android.model.ShareLinkMetaDTO
import dev.tunssh.android.model.SharePayloadDTO
import dev.tunssh.android.model.StatusDTO
import dev.tunssh.android.model.TunnelState
import dev.tunssh.android.vpn.VpnController
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = ProfileRepository(application)

    private val _profiles = MutableStateFlow<List<Profile>>(emptyList())
    val profiles: StateFlow<List<Profile>> = _profiles.asStateFlow()

    private val _settings = MutableStateFlow(AppSettings())
    val settings: StateFlow<AppSettings> = _settings.asStateFlow()

    val status: StateFlow<StatusDTO> = VpnController.status
    val hostKeyPrompt: StateFlow<HostKeyPromptDTO?> = VpnController.hostKeyPrompt
    val logs: StateFlow<List<LogEntryDTO>> = VpnController.logs
    val unreadAlertCount: StateFlow<Int> = VpnController.unreadAlertCount

    private val _pendingDeepLink = MutableStateFlow<String?>(null)
    val pendingDeepLink: StateFlow<String?> = _pendingDeepLink.asStateFlow()

    private val _toastMessage = MutableStateFlow<String?>(null)
    val toastMessage: StateFlow<String?> = _toastMessage.asStateFlow()

    init {
        reloadData()
        viewModelScope.launch {
            VpnController.profileVersion.collect {
                reloadData()
            }
        }
    }

    fun reloadData() {
        viewModelScope.launch(Dispatchers.IO) {
            val loadedProfiles = repository.listProfiles()
            val loadedSettings = repository.getSettings()
            _profiles.value = loadedProfiles
            _settings.value = loadedSettings
        }
    }

    fun selectProfile(profileId: String) {
        if (TunnelState.isActive(status.value.state)) return
        viewModelScope.launch(Dispatchers.IO) {
            val updated = repository.updateSettings { it.copy(selectedProfileId = profileId) }
            _settings.value = updated
        }
    }

    fun saveProfile(
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
        onComplete: (Profile) -> Unit = {},
    ) {
        viewModelScope.launch(Dispatchers.IO) {
            val existing = existingId?.let { repository.getProfile(it) }
            val existingSecrets = existingId?.let { repository.loadSecrets(it) } ?: ProfileSecrets()

            val nextSecrets = when (authType) {
                AuthType.KEY -> ProfileSecrets(
                    password = existingSecrets.password,
                    privateKey = if (privateKey.isNotBlank()) privateKey else existingSecrets.privateKey,
                    keyPassphrase = if (keyPassphrase.isNotEmpty() || privateKey.isNotBlank()) {
                        keyPassphrase
                    } else {
                        existingSecrets.keyPassphrase
                    },
                )
                else -> ProfileSecrets(
                    password = if (password.isNotEmpty() || existing == null) password else existingSecrets.password,
                    privateKey = existingSecrets.privateKey,
                    keyPassphrase = existingSecrets.keyPassphrase,
                )
            }

            val hostOrPortChanged = existing != null &&
                (existing.host != host.trim() || existing.port != port)

            val saved = repository.saveProfile(
                profile = Profile(
                    id = existing?.id.orEmpty(),
                    name = name,
                    host = host,
                    port = port,
                    username = username,
                    authType = authType,
                    bypassIranLan = bypassIranLan,
                    pinnedHostKey = if (hostOrPortChanged) null else existing?.pinnedHostKey,
                ),
                secrets = nextSecrets,
            )
            val updatedSettings = repository.updateSettings { it.copy(selectedProfileId = saved.id) }
            _profiles.value = repository.listProfiles()
            _settings.value = updatedSettings
            _toastMessage.value = if (existing == null) {
                "Created \"${saved.name}\""
            } else {
                "Updated \"${saved.name}\""
            }
            withContext(Dispatchers.Main) {
                onComplete(saved)
            }
        }
    }

    fun deleteProfile(profileId: String) {
        viewModelScope.launch(Dispatchers.IO) {
            repository.deleteProfile(profileId)
            _profiles.value = repository.listProfiles()
            _settings.value = repository.getSettings()
            _toastMessage.value = "Profile deleted"
        }
    }

    fun clearHostKey(profileId: String) {
        viewModelScope.launch(Dispatchers.IO) {
            repository.clearHostKey(profileId)
            _profiles.value = repository.listProfiles()
            _toastMessage.value = "Pinned host key cleared"
        }
    }

    fun toggleBypass(profileId: String, bypass: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            repository.setBypassIranLan(profileId, bypass)
            _profiles.value = repository.listProfiles()
            if (TunnelState.isActive(status.value.state)) {
                VpnController.toggleBypass(getApplication(), bypass)
            }
        }
    }

    fun setEnableIpv6(enabled: Boolean) {
        if (TunnelState.isActive(status.value.state)) return
        viewModelScope.launch(Dispatchers.IO) {
            _settings.value = repository.updateSettings { it.copy(enableIpv6 = enabled) }
        }
    }

    fun setDisallowedPackages(packages: Set<String>) {
        viewModelScope.launch(Dispatchers.IO) {
            val cleaned = packages - getApplication<Application>().packageName
            _settings.value = repository.updateSettings { it.copy(disallowedPackages = cleaned) }
            _toastMessage.value = if (TunnelState.isActive(status.value.state)) {
                "Split tunneling saved (applies on next reconnect)"
            } else {
                "Split tunneling updated (${cleaned.size} excluded)"
            }
        }
    }

    fun dismissBatteryBanner() {
        viewModelScope.launch(Dispatchers.IO) {
            _settings.value = repository.updateSettings { it.copy(batteryBannerDismissed = true) }
        }
    }

    fun startConnect(profileId: String) {
        VpnController.connect(getApplication(), profileId)
    }

    fun disconnect() {
        VpnController.disconnect(getApplication())
    }

    fun trustHostKeyAndConnect(prompt: HostKeyPromptDTO) {
        val targetId = resolvePromptProfileId(prompt)
        if (targetId.isBlank()) {
            _toastMessage.value = "No matching profile found for host key"
            VpnController.clearHostKeyPrompt()
            return
        }
        VpnController.trustHostKeyAndConnect(
            context = getApplication(),
            profileId = targetId,
            algorithm = prompt.algorithm,
            sha256 = prompt.sha256,
        )
    }

    fun forgetAndReconnect(prompt: HostKeyPromptDTO) {
        trustHostKeyAndConnect(prompt)
    }

    fun cancelHostKeyPrompt() {
        VpnController.clearHostKeyPrompt()
        if (TunnelState.isActive(status.value.state)) {
            VpnController.disconnect(getApplication())
        }
    }

    suspend fun inspectShareLink(link: String): ShareLinkMetaDTO = withContext(Dispatchers.IO) {
        VpnController.inspectShareLink(link)
    }

    suspend fun exportShareLink(
        profileId: String,
        passphrase: String,
        allowPlain: Boolean,
    ): String = withContext(Dispatchers.IO) {
        val profile = repository.getProfile(profileId)
            ?: throw IllegalArgumentException("Profile not found")
        val secrets = repository.loadSecrets(profileId)
        val secret = when (profile.authType) {
            AuthType.KEY -> secrets.privateKey
            else -> secrets.password
        }
        val payload = SharePayloadDTO(
            name = profile.name,
            host = profile.host,
            port = profile.port,
            user = profile.username,
            authType = profile.authType,
            secret = secret,
            keyPassphrase = if (profile.authType == AuthType.KEY) secrets.keyPassphrase else "",
            hostKey = profile.pinnedHostKey?.let {
                ShareHostKeyDTO(alg = it.algorithm, sha256 = it.sha256)
            },
        )
        VpnController.encodeShareLink(payload, passphrase, allowPlain)
    }

    suspend fun importShareLink(
        link: String,
        passphrase: String,
        allowPlain: Boolean,
    ): Profile = withContext(Dispatchers.IO) {
        val payload = VpnController.decodeShareLink(link, passphrase, allowPlain)
        val secrets = when (payload.authType) {
            AuthType.KEY -> ProfileSecrets(
                privateKey = payload.secret,
                keyPassphrase = payload.keyPassphrase,
            )
            else -> ProfileSecrets(password = payload.secret)
        }
        val saved = repository.saveProfile(
            profile = Profile(
                id = "",
                name = payload.name.ifBlank { "${payload.host}:${payload.port}" },
                host = payload.host,
                port = payload.port,
                username = payload.user,
                authType = payload.authType,
                bypassIranLan = true,
                pinnedHostKey = payload.hostKey?.let {
                    HostKeyPinDTO(algorithm = it.alg, sha256 = it.sha256)
                },
            ),
            secrets = secrets,
        )
        val updatedSettings = repository.updateSettings { it.copy(selectedProfileId = saved.id) }
        _profiles.value = repository.listProfiles()
        _settings.value = updatedSettings
        _toastMessage.value = "Imported \"${saved.name}\""
        saved
    }

    fun markLogsOpened() {
        VpnController.markAlertsRead()
    }

    fun clearLogs() {
        VpnController.clearLogs(getApplication())
    }

    fun exportRedactedLogsText(): String {
        return logs.value.joinToString("\n") { entry ->
            val codePart = if (entry.code.isNotEmpty()) " [${entry.code}]" else ""
            val hintPart = if (entry.actionHint.isNotEmpty()) " | Hint: ${entry.actionHint}" else ""
            "${entry.timestamp} ${entry.level}$codePart ${entry.message}$hintPart"
        }
    }

    fun setPendingDeepLink(uri: String?) {
        if (!uri.isNullOrBlank() && uri.startsWith("sshtun://", ignoreCase = true)) {
            _pendingDeepLink.value = uri
        }
    }

    fun consumeDeepLink() {
        _pendingDeepLink.value = null
    }

    fun showToast(message: String) {
        _toastMessage.value = message
    }

    fun consumeToast() {
        _toastMessage.value = null
    }

    private fun resolvePromptProfileId(prompt: HostKeyPromptDTO): String {
        val fromStatus = status.value.profileId
        if (fromStatus.isNotBlank()) return fromStatus
        val selected = settings.value.selectedProfileId
        if (!selected.isNullOrBlank()) return selected
        return profiles.value.firstOrNull {
            it.host.equals(prompt.host, ignoreCase = true) && it.port == prompt.port
        }?.id.orEmpty()
    }
}
