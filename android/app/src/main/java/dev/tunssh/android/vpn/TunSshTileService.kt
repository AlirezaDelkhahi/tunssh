package dev.tunssh.android.vpn

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import dev.tunssh.android.data.ProfileRepository
import dev.tunssh.android.model.StatusDTO
import dev.tunssh.android.model.TunnelState
import dev.tunssh.android.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class TunSshTileService : TileService() {

    private var tileScope: CoroutineScope? = null

    override fun onStartListening() {
        super.onStartListening()
        tileScope?.cancel()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        tileScope = scope
        scope.launch {
            VpnController.status.collect { status ->
                applyTileState(status)
            }
        }
    }

    override fun onStopListening() {
        tileScope?.cancel()
        tileScope = null
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        val currentState = VpnController.status.value.state
        if (TunnelState.isActive(currentState)) {
            VpnController.disconnect(this)
            return
        }

        val scope = tileScope ?: CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        scope.launch {
            val prepareIntent = VpnService.prepare(this@TunSshTileService)
            val activeProfile = withContext(Dispatchers.IO) {
                runCatching {
                    ProfileRepository(applicationContext).getActiveProfile()
                }.getOrNull()
            }
            if (prepareIntent != null || activeProfile == null) {
                openMainApp()
                return@launch
            }

            VpnController.connect(this@TunSshTileService, activeProfile.id)
        }
    }

    private suspend fun applyTileState(status: StatusDTO) {
        val tile = qsTile ?: return
        val activeProfile = withContext(Dispatchers.IO) {
            runCatching {
                ProfileRepository(applicationContext).getActiveProfile()
            }.getOrNull()
        }

        val isActive = TunnelState.isActive(status.state)
        tile.state = if (isActive) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = "tunssh"

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = when (status.state) {
                TunnelState.CONNECTED -> activeProfile?.name ?: "Connected"
                TunnelState.CONNECTING -> "Connecting..."
                TunnelState.RECONNECTING -> "Reconnecting..."
                TunnelState.ERROR -> "Error"
                else -> activeProfile?.name ?: "No profile"
            }
        }
        tile.updateTile()
    }

    private fun openMainApp() {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pi = PendingIntent.getActivity(
                this,
                201,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            startActivityAndCollapse(pi)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }
}
