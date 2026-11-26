package dev.tunssh.android.data

import android.content.Context
import dev.tunssh.android.model.AppSettings
import dev.tunssh.android.model.ConnectConfigDTO
import dev.tunssh.android.model.HostKeyPinDTO
import dev.tunssh.android.model.Profile
import dev.tunssh.android.model.ProfileSecrets
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.util.UUID

/**
 * Manages persisted SSH profile metadata (profiles.json), app settings (app_settings.json),
 * and hardware-backed credentials (KeystoreSecretStore).
 */
class ProfileRepository(context: Context) {

    private val appContext = context.applicationContext
    private val profilesFile = File(appContext.filesDir, "profiles.json")
    private val settingsFile = File(appContext.filesDir, "app_settings.json")
    private val secretStore = KeystoreSecretStore(appContext)
    private val lock = Any()

    fun listProfiles(): List<Profile> = synchronized(lock) {
        readProfilesLocked()
    }

    fun getProfile(profileId: String): Profile? = synchronized(lock) {
        readProfilesLocked().firstOrNull { it.id == profileId }
    }

    fun saveProfile(profile: Profile, secrets: ProfileSecrets?): Profile = synchronized(lock) {
        val now = System.currentTimeMillis() / 1000L
        val existingList = readProfilesLocked().toMutableList()
        val resolvedId = if (profile.id.isBlank()) {
            UUID.randomUUID().toString()
        } else {
            KeystoreSecretStore.validateProfileId(profile.id)
        }

        val existingIdx = existingList.indexOfFirst { it.id == resolvedId }
        val existing = if (existingIdx >= 0) existingList[existingIdx] else null

        val normalized = profile.copy(
            id = resolvedId,
            name = profile.name.trim().ifBlank { "${profile.host.trim()}:${profile.port}" },
            host = profile.host.trim(),
            username = profile.username.trim(),
            createdAtUnix = existing?.createdAtUnix?.takeIf { it > 0 } ?: profile.createdAtUnix.takeIf { it > 0 } ?: now,
            updatedAtUnix = now,
        )

        if (secrets != null) {
            secretStore.saveSecrets(resolvedId, secrets)
        } else if (existing == null) {
            secretStore.saveSecrets(resolvedId, ProfileSecrets())
        }

        if (existingIdx >= 0) {
            existingList[existingIdx] = normalized
        } else {
            existingList.add(normalized)
        }
        writeProfilesLocked(existingList)

        val settings = readSettingsLocked()
        if (settings.selectedProfileId.isNullOrBlank()) {
            writeSettingsLocked(settings.copy(selectedProfileId = normalized.id))
        }
        normalized
    }

    fun deleteProfile(profileId: String) = synchronized(lock) {
        val list = readProfilesLocked().filterNot { it.id == profileId }
        writeProfilesLocked(list)
        if (profileId.isNotBlank()) {
            runCatching { secretStore.deleteSecrets(profileId) }
        }
        val settings = readSettingsLocked()
        if (settings.selectedProfileId == profileId) {
            writeSettingsLocked(settings.copy(selectedProfileId = list.firstOrNull()?.id))
        }
    }

    fun pinHostKey(profileId: String, pin: HostKeyPinDTO): Profile? = synchronized(lock) {
        val list = readProfilesLocked().toMutableList()
        val idx = list.indexOfFirst { it.id == profileId }
        if (idx < 0) return null
        val updated = list[idx].copy(
            pinnedHostKey = pin,
            updatedAtUnix = System.currentTimeMillis() / 1000L,
        )
        list[idx] = updated
        writeProfilesLocked(list)
        updated
    }

    fun clearHostKey(profileId: String): Profile? = synchronized(lock) {
        val list = readProfilesLocked().toMutableList()
        val idx = list.indexOfFirst { it.id == profileId }
        if (idx < 0) return null
        val updated = list[idx].copy(
            pinnedHostKey = null,
            updatedAtUnix = System.currentTimeMillis() / 1000L,
        )
        list[idx] = updated
        writeProfilesLocked(list)
        updated
    }

    fun setBypassIranLan(profileId: String, bypass: Boolean): Profile? = synchronized(lock) {
        val list = readProfilesLocked().toMutableList()
        val idx = list.indexOfFirst { it.id == profileId }
        if (idx < 0) return null
        val updated = list[idx].copy(
            bypassIranLan = bypass,
            updatedAtUnix = System.currentTimeMillis() / 1000L,
        )
        list[idx] = updated
        writeProfilesLocked(list)
        updated
    }

    fun loadSecrets(profileId: String): ProfileSecrets = synchronized(lock) {
        secretStore.loadSecrets(profileId) ?: ProfileSecrets()
    }

    fun getSettings(): AppSettings = synchronized(lock) {
        readSettingsLocked()
    }

    fun updateSettings(transform: (AppSettings) -> AppSettings): AppSettings = synchronized(lock) {
        val next = transform(readSettingsLocked())
        writeSettingsLocked(next)
        next
    }

    fun getActiveProfile(): Profile? = synchronized(lock) {
        val profiles = readProfilesLocked()
        val selectedId = readSettingsLocked().selectedProfileId
        profiles.firstOrNull { it.id == selectedId } ?: profiles.firstOrNull()
    }

    fun buildConnectConfig(profileId: String, upstreamDns: List<String>): ConnectConfigDTO = synchronized(lock) {
        val profile = readProfilesLocked().firstOrNull { it.id == profileId }
            ?: throw IllegalArgumentException("Profile not found")
        val secrets = secretStore.loadSecrets(profile.id) ?: ProfileSecrets()
        val settings = readSettingsLocked()

        ConnectConfigDTO(
            profileId = profile.id,
            host = profile.host,
            port = profile.port,
            username = profile.username,
            authType = profile.authType,
            password = secrets.password,
            privateKey = secrets.privateKey,
            keyPassphrase = secrets.keyPassphrase,
            pinnedHostKey = profile.pinnedHostKey,
            bypassIranLan = profile.bypassIranLan,
            enableIpv6 = settings.enableIpv6,
            upstreamDns = upstreamDns,
        )
    }

    private fun readProfilesLocked(): List<Profile> {
        if (!profilesFile.exists()) return emptyList()
        return runCatching {
            val arr = JSONArray(profilesFile.readText(StandardCharsets.UTF_8))
            buildList(arr.length()) {
                for (i in 0 until arr.length()) {
                    val obj = arr.optJSONObject(i) ?: continue
                    val p = Profile.fromJson(obj)
                    if (p.id.isNotBlank()) add(p)
                }
            }
        }.getOrDefault(emptyList())
    }

    private fun writeProfilesLocked(profiles: List<Profile>) {
        val arr = JSONArray().apply {
            profiles.forEach { put(it.toJson()) }
        }
        writeAtomic(profilesFile, arr.toString(2).toByteArray(StandardCharsets.UTF_8))
    }

    private fun readSettingsLocked(): AppSettings {
        if (!settingsFile.exists()) return AppSettings()
        return runCatching {
            AppSettings.fromJson(JSONObject(settingsFile.readText(StandardCharsets.UTF_8)))
        }.getOrDefault(AppSettings())
    }

    private fun writeSettingsLocked(settings: AppSettings) {
        writeAtomic(settingsFile, settings.toJson().toString(2).toByteArray(StandardCharsets.UTF_8))
    }

    private fun writeAtomic(target: File, bytes: ByteArray) {
        val parent = target.parentFile
        if (parent != null && !parent.exists()) {
            parent.mkdirs()
        }
        val temp = File(parent, "${target.name}.tmp")
        FileOutputStream(temp).use { fos ->
            fos.write(bytes)
            fos.flush()
            fos.fd.sync()
        }
        if (!temp.renameTo(target)) {
            temp.delete()
            throw IllegalStateException("Failed to write ${target.name} atomically")
        }
    }
}
