package dev.tunssh.android.model

import org.json.JSONArray
import org.json.JSONObject

object TunnelState {
    const val DISCONNECTED = "disconnected"
    const val CONNECTING = "connecting"
    const val CONNECTED = "connected"
    const val RECONNECTING = "reconnecting"
    const val ERROR = "error"

    fun isActive(state: String): Boolean =
        state == CONNECTED || state == CONNECTING || state == RECONNECTING
}

object AuthType {
    const val PASSWORD = "password"
    const val KEY = "key"
}

object ShareMode {
    const val ENCRYPTED = "enc"
    const val PLAIN = "plain"
}

private fun JSONObject.optNonNullString(key: String, default: String = ""): String =
    if (isNull(key)) default else optString(key, default)

private fun JSONObject.optNonNullObject(key: String): JSONObject? =
    if (isNull(key)) null else optJSONObject(key)

private fun JSONObject.optNonNullArray(key: String): JSONArray? =
    if (isNull(key)) null else optJSONArray(key)

data class HostKeyPinDTO(
    val algorithm: String,
    val sha256: String,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("algorithm", algorithm)
        put("sha256", sha256)
    }

    companion object {
        fun fromJson(obj: JSONObject): HostKeyPinDTO = HostKeyPinDTO(
            algorithm = obj.optNonNullString("algorithm"),
            sha256 = obj.optNonNullString("sha256"),
        )
    }
}

data class ConnectConfigDTO(
    val profileId: String,
    val host: String,
    val port: Int,
    val username: String,
    val authType: String,
    val password: String = "",
    val privateKey: String = "",
    val keyPassphrase: String = "",
    val pinnedHostKey: HostKeyPinDTO? = null,
    val bypassIranLan: Boolean = true,
    val enableIpv6: Boolean = true,
    val upstreamDns: List<String> = emptyList(),
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("profile_id", profileId)
        put("host", host)
        put("port", port)
        put("username", username)
        put("auth_type", authType)
        put("password", password)
        put("private_key", privateKey)
        put("key_passphrase", keyPassphrase)
        put("pinned_host_key", pinnedHostKey?.toJson() ?: JSONObject.NULL)
        put("bypass_iran_lan", bypassIranLan)
        put("enable_ipv6", enableIpv6)
        put("upstream_dns", JSONArray().apply { upstreamDns.forEach { put(it) } })
    }

    fun toJsonString(): String = toJson().toString()

    companion object {
        fun fromJson(obj: JSONObject): ConnectConfigDTO {
            val dnsArr = obj.optNonNullArray("upstream_dns")
            val dnsList = buildList {
                if (dnsArr != null) {
                    for (i in 0 until dnsArr.length()) {
                        val item = dnsArr.optString(i, "")
                        if (item.isNotEmpty() && !dnsArr.isNull(i)) {
                            add(item)
                        }
                    }
                }
            }
            return ConnectConfigDTO(
                profileId = obj.optNonNullString("profile_id"),
                host = obj.optNonNullString("host"),
                port = obj.optInt("port", 22),
                username = obj.optNonNullString("username"),
                authType = obj.optNonNullString("auth_type", AuthType.PASSWORD),
                password = obj.optNonNullString("password"),
                privateKey = obj.optNonNullString("private_key"),
                keyPassphrase = obj.optNonNullString("key_passphrase"),
                pinnedHostKey = obj.optNonNullObject("pinned_host_key")?.let(HostKeyPinDTO::fromJson),
                bypassIranLan = obj.optBoolean("bypass_iran_lan", true),
                enableIpv6 = obj.optBoolean("enable_ipv6", false),
                upstreamDns = dnsList,
            )
        }

        fun fromJsonString(json: String): ConnectConfigDTO = fromJson(JSONObject(json))
    }
}

data class ErrorDTO(
    val code: String,
    val message: String,
    val actionHint: String = "",
    val retryable: Boolean = false,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("code", code)
        put("message", message)
        put("action_hint", actionHint)
        put("retryable", retryable)
    }

    companion object {
        fun fromJson(obj: JSONObject): ErrorDTO = ErrorDTO(
            code = obj.optNonNullString("code"),
            message = obj.optNonNullString("message"),
            actionHint = obj.optNonNullString("action_hint"),
            retryable = obj.optBoolean("retryable", false),
        )
    }
}

data class StatusDTO(
    val state: String = TunnelState.DISCONNECTED,
    val profileId: String = "",
    val attempt: Int = 0,
    val rttMs: Long = 0L,
    val rxBytes: Long = 0L,
    val txBytes: Long = 0L,
    val rxRateBps: Long = 0L,
    val txRateBps: Long = 0L,
    val connectedAtUnix: Long = 0L,
    val tunAttached: Boolean = false,
    val bypassIranLan: Boolean = true,
    val lastError: ErrorDTO? = null,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("state", state)
        put("profile_id", profileId)
        put("attempt", attempt)
        put("rtt_ms", rttMs)
        put("rx_bytes", rxBytes)
        put("tx_bytes", txBytes)
        put("rx_rate_bps", rxRateBps)
        put("tx_rate_bps", txRateBps)
        put("connected_at_unix", connectedAtUnix)
        put("tun_attached", tunAttached)
        put("bypass_iran_lan", bypassIranLan)
        put("last_error", lastError?.toJson() ?: JSONObject.NULL)
    }

    companion object {
        fun fromJson(obj: JSONObject): StatusDTO = StatusDTO(
            state = obj.optNonNullString("state", TunnelState.DISCONNECTED),
            profileId = obj.optNonNullString("profile_id"),
            attempt = obj.optInt("attempt", 0),
            rttMs = obj.optLong("rtt_ms", 0L),
            rxBytes = obj.optLong("rx_bytes", 0L),
            txBytes = obj.optLong("tx_bytes", 0L),
            rxRateBps = obj.optLong("rx_rate_bps", 0L),
            txRateBps = obj.optLong("tx_rate_bps", 0L),
            connectedAtUnix = obj.optLong("connected_at_unix", 0L),
            tunAttached = obj.optBoolean("tun_attached", false),
            bypassIranLan = obj.optBoolean("bypass_iran_lan", true),
            lastError = obj.optNonNullObject("last_error")?.let(ErrorDTO::fromJson),
        )

        fun fromJsonString(json: String): StatusDTO = fromJson(JSONObject(json))
    }
}

data class HostKeyPromptDTO(
    val host: String,
    val port: Int,
    val algorithm: String,
    val sha256: String,
    val mismatch: Boolean,
    val expectedAlgorithm: String = "",
    val expectedSha256: String = "",
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("host", host)
        put("port", port)
        put("algorithm", algorithm)
        put("sha256", sha256)
        put("mismatch", mismatch)
        if (expectedAlgorithm.isNotEmpty()) put("expected_algorithm", expectedAlgorithm)
        if (expectedSha256.isNotEmpty()) put("expected_sha256", expectedSha256)
    }

    companion object {
        fun fromJson(obj: JSONObject): HostKeyPromptDTO = HostKeyPromptDTO(
            host = obj.optNonNullString("host"),
            port = obj.optInt("port", 22),
            algorithm = obj.optNonNullString("algorithm"),
            sha256 = obj.optNonNullString("sha256"),
            mismatch = obj.optBoolean("mismatch", false),
            expectedAlgorithm = obj.optNonNullString("expected_algorithm"),
            expectedSha256 = obj.optNonNullString("expected_sha256"),
        )

        fun fromJsonString(json: String): HostKeyPromptDTO = fromJson(JSONObject(json))
    }
}

data class LogEntryDTO(
    val timestamp: String,
    val level: String,
    val message: String,
    val code: String = "",
    val actionHint: String = "",
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("timestamp", timestamp)
        put("level", level)
        put("message", message)
        if (code.isNotEmpty()) put("code", code)
        if (actionHint.isNotEmpty()) put("action_hint", actionHint)
    }

    companion object {
        fun fromJson(obj: JSONObject): LogEntryDTO = LogEntryDTO(
            timestamp = obj.optNonNullString("timestamp"),
            level = obj.optNonNullString("level", "INFO"),
            message = obj.optNonNullString("message"),
            code = obj.optNonNullString("code"),
            actionHint = obj.optNonNullString("action_hint"),
        )

        fun fromJsonString(json: String): LogEntryDTO = fromJson(JSONObject(json))

        fun listFromJsonArrayString(json: String): List<LogEntryDTO> {
            val arr = JSONArray(json)
            return buildList(arr.length()) {
                for (i in 0 until arr.length()) {
                    val item = arr.optJSONObject(i) ?: continue
                    add(fromJson(item))
                }
            }
        }
    }
}

data class CIDRRouteDTO(
    val address: String,
    val prefix: Int,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("address", address)
        put("prefix", prefix)
    }

    companion object {
        fun fromJson(obj: JSONObject): CIDRRouteDTO = CIDRRouteDTO(
            address = obj.optNonNullString("address"),
            prefix = obj.optInt("prefix", 0),
        )
    }
}

data class VPNPlanDTO(
    val tunIpv4Addr: String,
    val tunIpv4Prefix: Int,
    val tunIpv6Addr: String = "",
    val tunIpv6Prefix: Int = 0,
    val dnsIpv4: String,
    val mtu: Int,
    val routes: List<CIDRRouteDTO>,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("tun_ipv4_addr", tunIpv4Addr)
        put("tun_ipv4_prefix", tunIpv4Prefix)
        if (tunIpv6Addr.isNotEmpty()) put("tun_ipv6_addr", tunIpv6Addr)
        if (tunIpv6Prefix > 0) put("tun_ipv6_prefix", tunIpv6Prefix)
        put("dns_ipv4", dnsIpv4)
        put("mtu", mtu)
        put("routes", JSONArray().apply { routes.forEach { put(it.toJson()) } })
    }

    companion object {
        fun fromJson(obj: JSONObject): VPNPlanDTO {
            val routesArr = obj.optNonNullArray("routes")
            val routes = buildList {
                if (routesArr != null) {
                    for (i in 0 until routesArr.length()) {
                        val routeObj = routesArr.optJSONObject(i) ?: continue
                        add(CIDRRouteDTO.fromJson(routeObj))
                    }
                }
            }
            return VPNPlanDTO(
                tunIpv4Addr = obj.optNonNullString("tun_ipv4_addr"),
                tunIpv4Prefix = obj.optInt("tun_ipv4_prefix", 0),
                tunIpv6Addr = obj.optNonNullString("tun_ipv6_addr"),
                tunIpv6Prefix = obj.optInt("tun_ipv6_prefix", 0),
                dnsIpv4 = obj.optNonNullString("dns_ipv4"),
                mtu = obj.optInt("mtu", 1500),
                routes = routes,
            )
        }

        fun fromJsonString(json: String): VPNPlanDTO = fromJson(JSONObject(json))
    }
}

data class ShareLinkMetaDTO(
    val version: Int,
    val mode: String,
    val hasHostKey: Boolean,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("version", version)
        put("mode", mode)
        put("has_host_key", hasHostKey)
    }

    companion object {
        fun fromJson(obj: JSONObject): ShareLinkMetaDTO = ShareLinkMetaDTO(
            version = obj.optInt("version", 1),
            mode = obj.optNonNullString("mode"),
            hasHostKey = obj.optBoolean("has_host_key", false),
        )

        fun fromJsonString(json: String): ShareLinkMetaDTO = fromJson(JSONObject(json))
    }
}

data class ShareHostKeyDTO(
    val alg: String,
    val sha256: String,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("alg", alg)
        put("sha256", sha256)
    }

    companion object {
        fun fromJson(obj: JSONObject): ShareHostKeyDTO = ShareHostKeyDTO(
            alg = obj.optNonNullString("alg"),
            sha256 = obj.optNonNullString("sha256"),
        )
    }
}

data class SharePayloadDTO(
    val name: String,
    val host: String,
    val port: Int,
    val user: String,
    val authType: String,
    val secret: String,
    val keyPassphrase: String = "",
    val hostKey: ShareHostKeyDTO? = null,
    val mode: String = "",
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("name", name)
        put("host", host)
        put("port", port)
        put("user", user)
        put("auth_type", authType)
        put("secret", secret)
        if (keyPassphrase.isNotEmpty()) put("key_passphrase", keyPassphrase)
        if (hostKey != null) put("host_key", hostKey.toJson())
        if (mode.isNotEmpty()) put("mode", mode)
    }

    fun toJsonString(): String = toJson().toString()

    companion object {
        fun fromJson(obj: JSONObject): SharePayloadDTO = SharePayloadDTO(
            name = obj.optNonNullString("name"),
            host = obj.optNonNullString("host"),
            port = obj.optInt("port", 22),
            user = obj.optNonNullString("user"),
            authType = obj.optNonNullString("auth_type", AuthType.PASSWORD),
            secret = obj.optNonNullString("secret"),
            keyPassphrase = obj.optNonNullString("key_passphrase"),
            hostKey = obj.optNonNullObject("host_key")?.let(ShareHostKeyDTO::fromJson),
            mode = obj.optNonNullString("mode"),
        )

        fun fromJsonString(json: String): SharePayloadDTO = fromJson(JSONObject(json))
    }
}

/**
 * Persisted profile metadata stored in profiles.json.
 * Credentials are stored separately in KeystoreSecretStore and never serialized here.
 */
data class Profile(
    val id: String,
    val name: String,
    val host: String,
    val port: Int = 22,
    val username: String,
    val authType: String = AuthType.PASSWORD,
    val bypassIranLan: Boolean = true,
    val pinnedHostKey: HostKeyPinDTO? = null,
    val createdAtUnix: Long = 0L,
    val updatedAtUnix: Long = 0L,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("name", name)
        put("host", host)
        put("port", port)
        put("username", username)
        put("auth_type", authType)
        put("bypass_iran_lan", bypassIranLan)
        if (pinnedHostKey != null) {
            put("pinned_host_key", pinnedHostKey.toJson())
        }
        put("created_at_unix", createdAtUnix)
        put("updated_at_unix", updatedAtUnix)
    }

    companion object {
        fun fromJson(obj: JSONObject): Profile = Profile(
            id = obj.optNonNullString("id"),
            name = obj.optNonNullString("name"),
            host = obj.optNonNullString("host"),
            port = obj.optInt("port", 22),
            username = obj.optNonNullString("username"),
            authType = obj.optNonNullString("auth_type", AuthType.PASSWORD),
            bypassIranLan = obj.optBoolean("bypass_iran_lan", true),
            pinnedHostKey = obj.optNonNullObject("pinned_host_key")?.let(HostKeyPinDTO::fromJson),
            createdAtUnix = obj.optLong("created_at_unix", 0L),
            updatedAtUnix = obj.optLong("updated_at_unix", 0L),
        )
    }
}

/**
 * Sensitive credentials encrypted separately in AndroidKeyStore.
 */
data class ProfileSecrets(
    val password: String = "",
    val privateKey: String = "",
    val keyPassphrase: String = "",
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("password", password)
        put("private_key", privateKey)
        put("key_passphrase", keyPassphrase)
    }

    fun toJsonString(): String = toJson().toString()

    companion object {
        fun fromJson(obj: JSONObject): ProfileSecrets = ProfileSecrets(
            password = obj.optNonNullString("password"),
            privateKey = obj.optNonNullString("private_key"),
            keyPassphrase = obj.optNonNullString("key_passphrase"),
        )

        fun fromJsonString(json: String): ProfileSecrets = fromJson(JSONObject(json))
    }
}

data class AppSettings(
    val selectedProfileId: String? = null,
    val enableIpv6: Boolean = true,
    val disallowedPackages: Set<String> = emptySet(),
    val batteryBannerDismissed: Boolean = false,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        if (!selectedProfileId.isNullOrBlank()) {
            put("selected_profile_id", selectedProfileId)
        }
        put("enable_ipv6", enableIpv6)
        put("disallowed_packages", JSONArray().apply {
            disallowedPackages.sorted().forEach { put(it) }
        })
        put("battery_banner_dismissed", batteryBannerDismissed)
    }

    companion object {
        fun fromJson(obj: JSONObject): AppSettings {
            val pkgsArr = obj.optNonNullArray("disallowed_packages")
            val pkgs = buildSet {
                if (pkgsArr != null) {
                    for (i in 0 until pkgsArr.length()) {
                        val pkg = pkgsArr.optString(i, "").trim()
                        if (pkg.isNotEmpty() && !pkgsArr.isNull(i)) {
                            add(pkg)
                        }
                    }
                }
            }
            val selected = obj.optNonNullString("selected_profile_id").ifBlank { null }
            return AppSettings(
                selectedProfileId = selected,
                enableIpv6 = obj.optBoolean("enable_ipv6", true),
                disallowedPackages = pkgs,
                batteryBannerDismissed = obj.optBoolean("battery_banner_dismissed", false),
            )
        }
    }
}
