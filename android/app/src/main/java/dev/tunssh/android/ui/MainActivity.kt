package dev.tunssh.android.ui

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color as AndroidColor
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import dev.tunssh.android.ui.theme.TunSshTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.nio.charset.StandardCharsets

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    private var pendingConnectProfileId: String? = null
    private var pickedPrivateKeyState by mutableStateOf<String?>(null)
    private var batteryCheckVersion by mutableIntStateOf(0)
    private var showQrScannerState by mutableStateOf(false)
    private var pickedQrLinkState by mutableStateOf<String?>(null)

    private val vpnPrepareLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val profileId = pendingConnectProfileId
        pendingConnectProfileId = null
        if (result.resultCode == RESULT_OK && !profileId.isNullOrBlank()) {
            viewModel.startConnect(profileId)
        } else if (result.resultCode != RESULT_OK) {
            viewModel.showToast("VPN permission is required to start the tunnel")
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {
        val profileId = pendingConnectProfileId
        if (!profileId.isNullOrBlank()) {
            launchVpnConsentOrConnect(profileId)
        }
    }

    private val pemPickerLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        if (uri == null) return@registerForActivityResult
        lifecycleScope.launch {
            val content = withContext(Dispatchers.IO) {
                readKeyUriText(uri)
            }
            if (content.isNullOrBlank()) {
                viewModel.showToast("Failed to read private key file")
            } else {
                pickedPrivateKeyState = content
            }
        }
    }

    private val batteryOptLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) {
        batteryCheckVersion++
    }

    private val cameraPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            showQrScannerState = true
        } else {
            viewModel.showToast("Camera permission is required to scan QR codes")
        }
    }

    private val qrImagePickerLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri: Uri? ->
        if (uri == null) return@registerForActivityResult
        lifecycleScope.launch {
            val decoded = withContext(Dispatchers.IO) {
                decodeQrFromImageUri(uri)
            }
            val trimmed = decoded?.trim()
            if (!trimmed.isNullOrEmpty() && trimmed.startsWith("sshtun://", ignoreCase = true)) {
                pickedQrLinkState = trimmed
            } else {
                viewModel.showToast("No valid sshtun:// QR code found in image")
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val canvasColor = AndroidColor.parseColor("#0B0F17")
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(canvasColor),
            navigationBarStyle = SystemBarStyle.dark(canvasColor),
        )

        handleIncomingIntent(intent)

        setContent {
            // Re-read battery optimization state whenever user returns from Settings.
            val checkTick = batteryCheckVersion
            val ignoringBattery = checkTick >= 0 && isIgnoringBatteryOptimizations()

            TunSshTheme {
                TunSshScreen(
                    viewModel = viewModel,
                    isIgnoringBatteryOptimizations = ignoringBattery,
                    pickedPrivateKey = pickedPrivateKeyState,
                    onConsumePickedPrivateKey = { pickedPrivateKeyState = null },
                    showQrScanner = showQrScannerState,
                    pickedQrLink = pickedQrLinkState,
                    onConsumePickedQrLink = { pickedQrLinkState = null },
                    onRequestScanQrCamera = { requestScanQrCamera() },
                    onRequestPickQrImage = { qrImagePickerLauncher.launch("image/*") },
                    onQrScannedFromCamera = { link ->
                        showQrScannerState = false
                        pickedQrLinkState = link
                    },
                    onDismissQrScanner = { showQrScannerState = false },
                    onRequestConnectWithPermissions = { profileId ->
                        requestConnectFlow(profileId)
                    },
                    onRequestPickPemFile = {
                        pemPickerLauncher.launch(arrayOf("*/*"))
                    },
                    onRequestIgnoreBatteryOptimizations = {
                        requestIgnoreBatteryOptimizations()
                    },
                    onShareViaSystemSheet = { link ->
                        shareText(link)
                    },
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        batteryCheckVersion++
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingIntent(intent)
    }

    private fun handleIncomingIntent(intent: Intent?) {
        if (intent?.action == Intent.ACTION_VIEW) {
            val data = intent.data
            if (data != null && "sshtun".equals(data.scheme, ignoreCase = true)) {
                viewModel.setPendingDeepLink(data.toString())
            }
        }
    }

    private fun requestConnectFlow(profileId: String) {
        pendingConnectProfileId = profileId
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }
        launchVpnConsentOrConnect(profileId)
    }

    private fun launchVpnConsentOrConnect(profileId: String) {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            pendingConnectProfileId = profileId
            vpnPrepareLauncher.launch(prepareIntent)
        } else {
            pendingConnectProfileId = null
            viewModel.startConnect(profileId)
        }
    }

    private fun isIgnoringBatteryOptimizations(): Boolean {
        val pm = getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return true
        return pm.isIgnoringBatteryOptimizations(packageName)
    }

    @SuppressLint("BatteryLife")
    private fun requestIgnoreBatteryOptimizations() {
        val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
            data = Uri.parse("package:$packageName")
        }
        runCatching {
            batteryOptLauncher.launch(intent)
        }.onFailure {
            viewModel.showToast("Open Android Settings -> Battery to allow unrestricted usage")
        }
    }

    private fun shareText(link: String) {
        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, link)
        }
        startActivity(Intent.createChooser(sendIntent, "Share tunssh profile"))
    }

    private fun requestScanQrCamera() {
        val granted = ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.CAMERA,
        ) == PackageManager.PERMISSION_GRANTED
        if (granted) {
            showQrScannerState = true
        } else {
            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    private fun decodeQrFromImageUri(uri: Uri): String? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        runCatching {
            contentResolver.openInputStream(uri)?.use { stream ->
                BitmapFactory.decodeStream(stream, null, bounds)
            }
        }
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) {
            return null
        }

        var sampleSize = 1
        while ((bounds.outWidth / sampleSize) > 1600 || (bounds.outHeight / sampleSize) > 1600) {
            sampleSize *= 2
        }

        val decodeOpts = BitmapFactory.Options().apply {
            inSampleSize = sampleSize
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        val bitmap = runCatching {
            contentResolver.openInputStream(uri)?.use { stream ->
                BitmapFactory.decodeStream(stream, null, decodeOpts)
            }
        }.getOrNull() ?: return null

        return try {
            QrCodeUtils.decodeQrFromBitmap(bitmap)
        } finally {
            bitmap.recycle()
        }
    }

    private fun readKeyUriText(uri: Uri): String? {
        return runCatching {
            contentResolver.openInputStream(uri)?.use { stream ->
                val maxBytes = 64 * 1024
                val buffer = ByteArray(maxBytes + 1)
                var total = 0
                while (total < buffer.size) {
                    val read = stream.read(buffer, total, buffer.size - total)
                    if (read <= 0) break
                    total += read
                }
                if (total > maxBytes) {
                    return null
                }
                String(buffer, 0, total, StandardCharsets.UTF_8)
            }
        }.getOrNull()
    }
}
