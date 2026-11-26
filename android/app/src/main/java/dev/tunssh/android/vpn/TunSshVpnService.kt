package dev.tunssh.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import androidx.core.app.NotificationCompat
import dev.tunssh.android.R
import dev.tunssh.android.data.ProfileRepository
import dev.tunssh.android.model.ErrorDTO
import dev.tunssh.android.model.HostKeyPinDTO
import dev.tunssh.android.model.HostKeyPromptDTO
import dev.tunssh.android.model.LogEntryDTO
import dev.tunssh.android.model.StatusDTO
import dev.tunssh.android.model.TunnelState
import dev.tunssh.android.model.VPNPlanDTO
import dev.tunssh.android.ui.FormatUtils
import dev.tunssh.android.ui.MainActivity
import dev.tunssh.mobile.Engine
import dev.tunssh.mobile.EventListener
import dev.tunssh.mobile.Mobile
import dev.tunssh.mobile.SocketProtector
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class TunSshVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val opMutex = Mutex()
    private val callbackRegistered = AtomicBoolean(false)
    private val connectGeneration = AtomicLong(0L)

    private lateinit var repository: ProfileRepository
    private lateinit var connectivityManager: ConnectivityManager
    private lateinit var notificationManager: NotificationManager
    private lateinit var engine: Engine

    @Volatile
    private var activeConnectJob: Job? = null

    @Volatile
    private var activeHostLabel: String = ""

    @Volatile
    private var activeProfileId: String = ""

    @Volatile
    private var lastNotificationState: String = ""

    @Volatile
    private var lastDnsSignature: String = ""

    @Volatile
    private var trackedPhysicalNetwork: Network? = null

    @Volatile
    private var vpnEstablished: Boolean = false

    @Volatile
    private var suppressDisconnectCallback: Boolean = false

    @Volatile
    private var activeBypassIranLan: Boolean = true

    @Volatile
    private var activeEnableIpv6: Boolean = true

    @Volatile
    private var activeDisallowedPackages: Set<String> = emptySet()

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            trackedPhysicalNetwork = network
            pushUpstreamDnsForNetwork(network, force = true)
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            if (trackedPhysicalNetwork == null || trackedPhysicalNetwork == network) {
                trackedPhysicalNetwork = network
                pushUpstreamDnsFromLinkProperties(linkProperties, force = false)
            }
        }

        override fun onLost(network: Network) {
            if (trackedPhysicalNetwork == network) {
                trackedPhysicalNetwork = null
                val fallback = findActivePhysicalNetwork()
                if (fallback != null) {
                    trackedPhysicalNetwork = fallback
                    pushUpstreamDnsForNetwork(fallback, force = true)
                } else {
                    notifyEngineDnsChanged(emptyList(), force = true)
                }
            }
        }
    }

    private val engineListener = object : EventListener {
        override fun onStatusChanged(statusJSON: String?) {
            val raw = statusJSON ?: return
            val dto = runCatching { StatusDTO.fromJsonString(raw) }.getOrNull() ?: return
            if (dto.state == TunnelState.DISCONNECTED && suppressDisconnectCallback) {
                return
            }
            VpnController.onStatusFromEngine(dto)
            if (dto.state != lastNotificationState) {
                lastNotificationState = dto.state
                VpnController.requestTileUpdate(this@TunSshVpnService)
            }
            if (TunnelState.isActive(dto.state)) {
                updateNotification(dto)
            } else if (dto.state == TunnelState.ERROR && vpnEstablished) {
                val eventGen = connectGeneration.get()
                serviceScope.launch {
                    opMutex.withLock {
                        if (connectGeneration.get() != eventGen) return@withLock
                        if (vpnEstablished) {
                            stopVpnPreservingError(eventGen, dto)
                        }
                    }
                }
            }
        }

        override fun onHostKeyPrompt(promptJSON: String?) {
            val raw = promptJSON ?: return
            val dto = runCatching { HostKeyPromptDTO.fromJsonString(raw) }.getOrNull() ?: return
            VpnController.onHostKeyPromptFromEngine(dto)
        }

        override fun onLog(entryJSON: String?) {
            val raw = entryJSON ?: return
            val dto = runCatching { LogEntryDTO.fromJsonString(raw) }.getOrNull() ?: return
            VpnController.onLogFromEngine(dto)
        }
    }

    override fun onCreate() {
        super.onCreate()
        repository = ProfileRepository(applicationContext)
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        ensureNotificationChannel()

        engine = Mobile.newEngine(engineListener)
        runCatching {
            val existingLogs = LogEntryDTO.listFromJsonArrayString(engine.logsJson())
            if (existingLogs.isNotEmpty()) {
                VpnController.setLogsSnapshot(existingLogs)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val profileId = intent.getStringExtra(EXTRA_PROFILE_ID).orEmpty()
                promoteToForeground("Connecting...", activeHostLabel)
                launchConnect(profileId)
            }

            ACTION_TRUST_HOSTKEY -> {
                val profileId = intent.getStringExtra(EXTRA_PROFILE_ID).orEmpty()
                val alg = intent.getStringExtra(EXTRA_HOSTKEY_ALG).orEmpty()
                val sha256 = intent.getStringExtra(EXTRA_HOSTKEY_SHA256).orEmpty()
                promoteToForeground("Pinning host key...", activeHostLabel)
                launchTrustAndConnect(profileId, alg, sha256)
            }

            ACTION_TOGGLE_BYPASS -> {
                val bypass = intent.getBooleanExtra(EXTRA_BYPASS_IRAN_LAN, true)
                val eventGen = connectGeneration.get()
                serviceScope.launch {
                    opMutex.withLock {
                        if (connectGeneration.get() != eventGen) return@withLock
                        if (!vpnEstablished) return@withLock
                        activeBypassIranLan = bypass
                        try {
                            engine.setBypass(bypass)
                            val plan = VpnController.buildVpnPlan(
                                bypassIranLan = bypass,
                                enableIpv6 = activeEnableIpv6,
                                mtu = 0,
                            )
                            val newPfd = buildVpnBuilder(plan, activeDisallowedPackages).establish()
                            if (newPfd == null) {
                                emitFailureAndStop(
                                    gen = eventGen,
                                    profileId = activeProfileId,
                                    code = "ERR_VPN_ESTABLISH",
                                    message = "Android refused to update VPN routes.",
                                    actionHint = "Disconnect and reconnect the tunnel.",
                                    retryable = true,
                                )
                                return@withLock
                            }
                            val newFd = newPfd.detachFd()
                            engine.replaceTun(newFd)
                            updateNotification(VpnController.status.value.copy(bypassIranLan = bypass))
                        } catch (e: Exception) {
                            emitFailureAndStop(
                                gen = eventGen,
                                profileId = activeProfileId,
                                code = "ERR_TUN_REPLACE",
                                message = e.message ?: "Failed to update bypass routes",
                                actionHint = "Disconnect and reconnect the tunnel.",
                                retryable = true,
                            )
                        }
                    }
                }
            }

            ACTION_CLEAR_LOGS -> {
                runCatching { engine.clearLogs() }
            }

            ACTION_DISCONNECT -> {
                launchDisconnect()
            }

            else -> {
                // System restarted service or null intent with no active session; shut down cleanly.
                if (!TunnelState.isActive(VpnController.status.value.state)) {
                    stopSelf()
                }
            }
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        launchDisconnect()
        super.onRevoke()
    }

    override fun onDestroy() {
        connectGeneration.incrementAndGet()
        activeConnectJob?.cancel()
        unregisterNetworkCallback()
        val isTerminalError = VpnController.status.value.state == TunnelState.ERROR
        if (isTerminalError) {
            suppressDisconnectCallback = true
        }
        vpnEstablished = false
        CoroutineScope(Dispatchers.IO).launch {
            runCatching { engine.stop() }
        }
        if (!isTerminalError) {
            VpnController.onStatusFromEngine(
                StatusDTO(
                    state = TunnelState.DISCONNECTED,
                    profileId = activeProfileId,
                ),
            )
        }
        VpnController.requestTileUpdate(this)
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun launchTrustAndConnect(profileId: String, algorithm: String, sha256: String) {
        val gen = connectGeneration.incrementAndGet()
        val prevJob = activeConnectJob
        val wasRunning = prevJob != null && !prevJob.isCompleted
        prevJob?.cancel()
        activeConnectJob = serviceScope.launch {
            if (wasRunning) {
                suppressDisconnectCallback = true
                runCatching { engine.stop() }
                prevJob?.join()
            }
            opMutex.withLock {
                if (connectGeneration.get() != gen) return@withLock
                if (profileId.isNotBlank() && algorithm.isNotBlank() && sha256.isNotBlank()) {
                    repository.pinHostKey(
                        profileId,
                        HostKeyPinDTO(algorithm = algorithm, sha256 = sha256),
                    )
                    VpnController.notifyProfilesChanged()
                }
                connectInternal(profileId, gen)
            }
        }
    }

    private fun launchConnect(profileId: String) {
        val gen = connectGeneration.incrementAndGet()
        val prevJob = activeConnectJob
        val wasRunning = prevJob != null && !prevJob.isCompleted
        prevJob?.cancel()
        activeConnectJob = serviceScope.launch {
            if (wasRunning) {
                suppressDisconnectCallback = true
                runCatching { engine.stop() }
                prevJob?.join()
            }
            opMutex.withLock {
                if (connectGeneration.get() != gen) return@withLock
                connectInternal(profileId, gen)
            }
        }
    }

    private fun launchDisconnect() {
        val gen = connectGeneration.incrementAndGet()
        suppressDisconnectCallback = false
        activeConnectJob?.cancel()
        serviceScope.launch {
            // Interrupt in-flight ConnectSsh immediately off the main thread.
            runCatching { engine.stop() }
            opMutex.withLock {
                if (connectGeneration.get() == gen) {
                    disconnectInternal(gen)
                }
            }
        }
    }

    private suspend fun connectInternal(requestedProfileId: String, gen: Long) {
        try {
            if (VpnService.prepare(this@TunSshVpnService) != null) {
                emitFailureAndStop(
                    gen = gen,
                    profileId = requestedProfileId,
                    code = "ERR_VPN_PERMISSION",
                    message = "Android VPN permission is required.",
                    actionHint = "Open tunssh and grant VPN permission when prompted.",
                    retryable = false,
                )
                return
            }

            unregisterNetworkCallback()
            suppressDisconnectCallback = true
            vpnEstablished = false
            runCatching { engine.stop() }
            suppressDisconnectCallback = false

            val profile = if (requestedProfileId.isNotBlank()) {
                repository.getProfile(requestedProfileId)
            } else {
                repository.getActiveProfile()
            }

            if (profile == null) {
                emitFailureAndStop(
                    gen = gen,
                    profileId = requestedProfileId,
                    code = "ERR_PROFILE_NOT_FOUND",
                    message = "No SSH profile is available.",
                    actionHint = "Create or select a server profile before connecting.",
                    retryable = false,
                )
                return
            }

            activeProfileId = profile.id
            activeHostLabel = "${profile.host}:${profile.port}"
            updateNotificationText("Connecting...", activeHostLabel)

            val initialDns = queryCurrentPhysicalDns()
            val config = repository.buildConnectConfig(profile.id, initialDns)
            val settings = repository.getSettings()
            activeBypassIranLan = config.bypassIranLan
            activeEnableIpv6 = config.enableIpv6
            activeDisallowedPackages = settings.disallowedPackages

            // Phase 1: Establish SSH session BEFORE VpnService.Builder.establish().
            // If ConnectSsh fails (TOFU prompt, host-key mismatch, auth error, network error),
            // we tear down without ever creating a TUN interface while preserving ErrorDTO.
            try {
                engine.connectSsh(
                    config.toJsonString(),
                    SocketProtector { fd -> protect(fd) },
                )
            } catch (e: Exception) {
                if (connectGeneration.get() != gen) {
                    suppressDisconnectCallback = true
                    runCatching { engine.stop() }
                    return
                }
                val currentStatus = VpnController.status.value
                val preservedError = if (currentStatus.state == TunnelState.ERROR && currentStatus.lastError != null) {
                    currentStatus.lastError
                } else {
                    ErrorDTO(
                        code = "ERR_NETWORK",
                        message = e.message ?: "SSH connection failed",
                        actionHint = "Verify server address, port, credentials, and internet access.",
                        retryable = true,
                    )
                }
                suppressDisconnectCallback = true
                vpnEstablished = false
                runCatching { engine.stop() }
                if (connectGeneration.get() == gen) {
                    VpnController.onStatusFromEngine(
                        StatusDTO(
                            state = TunnelState.ERROR,
                            profileId = profile.id,
                            tunAttached = false,
                            bypassIranLan = config.bypassIranLan,
                            lastError = preservedError,
                        ),
                    )
                    VpnController.requestTileUpdate(this@TunSshVpnService)
                    stopForegroundAndSelf()
                }
                return
            }

            if (connectGeneration.get() != gen) {
                suppressDisconnectCallback = true
                runCatching { engine.stop() }
                return
            }

            // Phase 2: Build VPN routing plan and establish Android TUN interface.
            val plan = VpnController.buildVpnPlan(
                bypassIranLan = config.bypassIranLan,
                enableIpv6 = config.enableIpv6,
                mtu = 0,
            )

            val pfd = buildVpnBuilder(plan, activeDisallowedPackages).establish()
            if (pfd == null) {
                emitFailureAndStop(
                    gen = gen,
                    profileId = profile.id,
                    code = "ERR_VPN_ESTABLISH",
                    message = "Android refused to establish the VPN interface.",
                    actionHint = "Ensure no other always-on VPN is locking the VPN slot and retry.",
                    retryable = true,
                )
                return
            }

            if (connectGeneration.get() != gen) {
                runCatching { pfd.close() }
                suppressDisconnectCallback = true
                runCatching { engine.stop() }
                return
            }

            // Hand raw TUN FD ownership directly to Go; never touch or close pfd afterward.
            val tunFd = pfd.detachFd()
            try {
                engine.attachTun(tunFd)
            } catch (e: Exception) {
                emitFailureAndStop(
                    gen = gen,
                    profileId = profile.id,
                    code = "ERR_TUN_ATTACH",
                    message = e.message ?: "Failed to attach TUN runner",
                    actionHint = "Disconnect and reconnect the tunnel.",
                    retryable = true,
                )
                return
            }

            vpnEstablished = true
            registerNetworkCallback()
            updateNotificationText("Connected", activeHostLabel)
            VpnController.requestTileUpdate(this@TunSshVpnService)
        } catch (ce: CancellationException) {
            if (connectGeneration.get() == gen) {
                suppressDisconnectCallback = true
                vpnEstablished = false
                runCatching { engine.stop() }
                stopForegroundAndSelf()
            }
            throw ce
        } catch (e: Exception) {
            emitFailureAndStop(
                gen = gen,
                profileId = activeProfileId,
                code = "ERR_NETWORK",
                message = e.message ?: "Unexpected VPN service error",
                actionHint = "Inspect diagnostic logs and try again.",
                retryable = true,
            )
        }
    }

    private fun buildVpnBuilder(plan: VPNPlanDTO, disallowedPackages: Set<String>): Builder {
        val builder = Builder()
            .setSession("tunssh")
            .setMtu(plan.mtu)
            .addAddress(plan.tunIpv4Addr, plan.tunIpv4Prefix)
            .addDnsServer(plan.dnsIpv4)
            .setConfigureIntent(mainActivityPendingIntent())

        if (plan.tunIpv6Addr.isNotBlank() && plan.tunIpv6Prefix > 0) {
            builder.addAddress(plan.tunIpv6Addr, plan.tunIpv6Prefix)
        }

        for (route in plan.routes) {
            builder.addRoute(route.address, route.prefix)
        }

        for (pkg in disallowedPackages) {
            if (pkg == packageName || pkg.isBlank()) continue
            try {
                builder.addDisallowedApplication(pkg)
            } catch (_: PackageManager.NameNotFoundException) {
                // Ignore uninstalled apps safely.
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        return builder
    }

    private fun disconnectInternal(gen: Long) {
        suppressDisconnectCallback = false
        vpnEstablished = false
        unregisterNetworkCallback()
        runCatching { engine.stop() }
        if (connectGeneration.get() == gen) {
            VpnController.onStatusFromEngine(
                StatusDTO(
                    state = TunnelState.DISCONNECTED,
                    profileId = activeProfileId,
                ),
            )
            VpnController.requestTileUpdate(this@TunSshVpnService)
            stopForegroundAndSelf()
        }
    }

    private fun stopVpnPreservingError(gen: Long, errorStatus: StatusDTO) {
        suppressDisconnectCallback = true
        vpnEstablished = false
        unregisterNetworkCallback()
        runCatching { engine.stop() }
        if (connectGeneration.get() == gen) {
            VpnController.onStatusFromEngine(errorStatus.copy(tunAttached = false))
            VpnController.requestTileUpdate(this@TunSshVpnService)
            stopForegroundAndSelf()
        }
    }

    private fun emitFailureAndStop(
        gen: Long,
        profileId: String,
        code: String,
        message: String,
        actionHint: String,
        retryable: Boolean,
    ) {
        suppressDisconnectCallback = true
        vpnEstablished = false
        unregisterNetworkCallback()
        runCatching { engine.stop() }
        if (connectGeneration.get() == gen) {
            VpnController.onStatusFromEngine(
                StatusDTO(
                    state = TunnelState.ERROR,
                    profileId = profileId,
                    tunAttached = false,
                    bypassIranLan = activeBypassIranLan,
                    lastError = ErrorDTO(
                        code = code,
                        message = message,
                        actionHint = actionHint,
                        retryable = retryable,
                    ),
                ),
            )
            VpnController.requestTileUpdate(this@TunSshVpnService)
            stopForegroundAndSelf()
        }
    }

    private fun registerNetworkCallback() {
        if (!callbackRegistered.compareAndSet(false, true)) {
            return
        }
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        try {
            connectivityManager.registerNetworkCallback(request, networkCallback)
        } catch (_: Exception) {
            callbackRegistered.set(false)
        }
    }

    private fun unregisterNetworkCallback() {
        if (callbackRegistered.compareAndSet(true, false)) {
            runCatching { connectivityManager.unregisterNetworkCallback(networkCallback) }
        }
        trackedPhysicalNetwork = null
        lastDnsSignature = ""
    }

    private fun findActivePhysicalNetwork(): Network? {
        val active = connectivityManager.activeNetwork
        if (active != null && isPhysicalInternetNetwork(active)) {
            return active
        }
        @Suppress("DEPRECATION")
        val all = connectivityManager.allNetworks
        return all.firstOrNull { isPhysicalInternetNetwork(it) }
    }

    private fun isPhysicalInternetNetwork(network: Network): Boolean {
        val caps = connectivityManager.getNetworkCapabilities(network) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
    }

    private fun queryCurrentPhysicalDns(): List<String> {
        val net = findActivePhysicalNetwork() ?: return emptyList()
        trackedPhysicalNetwork = net
        val lp = connectivityManager.getLinkProperties(net) ?: return emptyList()
        return extractUsableDnsServers(lp)
    }

    private fun pushUpstreamDnsForNetwork(network: Network, force: Boolean) {
        val lp = connectivityManager.getLinkProperties(network) ?: return
        pushUpstreamDnsFromLinkProperties(lp, force)
    }

    private fun pushUpstreamDnsFromLinkProperties(lp: LinkProperties, force: Boolean) {
        notifyEngineDnsChanged(extractUsableDnsServers(lp), force)
    }

    private fun extractUsableDnsServers(lp: LinkProperties): List<String> {
        return lp.dnsServers
            .asSequence()
            .filter { addr ->
                !addr.isLoopbackAddress &&
                    !addr.isAnyLocalAddress &&
                    !addr.isMulticastAddress &&
                    !addr.isLinkLocalAddress
            }
            .mapNotNull { addr ->
                addr.hostAddress?.substringBefore('%')?.trim()?.takeIf { it.isNotEmpty() }
            }
            .distinct()
            .toList()
    }

    private fun notifyEngineDnsChanged(dnsServers: List<String>, force: Boolean) {
        val arr = JSONArray().apply { dnsServers.forEach { put(it) } }
        val json = arr.toString()
        if (!force && json == lastDnsSignature) {
            return
        }
        lastDnsSignature = json
        serviceScope.launch {
            runCatching { engine.notifyNetworkChanged(json) }
        }
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.vpn_notification_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = getString(R.string.vpn_notification_channel_desc)
                setShowBadge(false)
            }
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun promoteToForeground(titleState: String, body: String) {
        val notification = buildNotification(titleState, body)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun updateNotification(status: StatusDTO) {
        val stateLabel = when (status.state) {
            TunnelState.CONNECTED -> "Connected"
            TunnelState.CONNECTING -> "Connecting..."
            TunnelState.RECONNECTING -> "Reconnecting (#${status.attempt.coerceAtLeast(1)})"
            else -> "Active"
        }
        val body = if (status.state == TunnelState.CONNECTED) {
            val rx = FormatUtils.formatBytes(status.rxBytes)
            val tx = FormatUtils.formatBytes(status.txBytes)
            if (activeHostLabel.isNotBlank()) {
                "$activeHostLabel • ↓ $rx  ↑ $tx"
            } else {
                "↓ $rx  ↑ $tx"
            }
        } else {
            activeHostLabel.ifBlank { "Establishing SSH tunnel..." }
        }
        updateNotificationText(stateLabel, body)
    }

    private fun updateNotificationText(titleState: String, body: String) {
        notificationManager.notify(NOTIFICATION_ID, buildNotification(titleState, body))
    }

    private fun buildNotification(titleState: String, body: String): Notification {
        val disconnectIntent = Intent(this, TunSshVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val disconnectPi = PendingIntent.getService(
            this,
            REQ_DISCONNECT,
            disconnectIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_notification)
            .setContentTitle("tunssh • $titleState")
            .setContentText(body.ifBlank { "SSH TUN active" })
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(mainActivityPendingIntent())
            .addAction(0, getString(R.string.action_disconnect), disconnectPi)
            .build()
    }

    private fun mainActivityPendingIntent(): PendingIntent {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        return PendingIntent.getActivity(
            this,
            REQ_OPEN_UI,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private fun stopForegroundAndSelf() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    companion object {
        const val ACTION_CONNECT = "dev.tunssh.android.action.CONNECT"
        const val ACTION_DISCONNECT = "dev.tunssh.android.action.DISCONNECT"
        const val ACTION_TOGGLE_BYPASS = "dev.tunssh.android.action.TOGGLE_BYPASS"
        const val ACTION_TRUST_HOSTKEY = "dev.tunssh.android.action.TRUST_HOSTKEY"
        const val ACTION_CLEAR_LOGS = "dev.tunssh.android.action.CLEAR_LOGS"

        const val EXTRA_PROFILE_ID = "extra_profile_id"
        const val EXTRA_BYPASS_IRAN_LAN = "extra_bypass_iran_lan"
        const val EXTRA_HOSTKEY_ALG = "extra_hostkey_alg"
        const val EXTRA_HOSTKEY_SHA256 = "extra_hostkey_sha256"

        private const val CHANNEL_ID = "tunssh_vpn_status"
        private const val NOTIFICATION_ID = 1001
        private const val REQ_OPEN_UI = 100
        private const val REQ_DISCONNECT = 101
    }
}
