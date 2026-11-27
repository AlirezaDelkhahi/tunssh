package dev.tunssh.android.ui.components

import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import dev.tunssh.android.ui.QrCodeUtils
import dev.tunssh.android.ui.theme.TunSshColors
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

@Composable
fun QrScannerDialog(
    onQrScanned: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    val analyzerExecutor = remember(lifecycleOwner) { Executors.newSingleThreadExecutor() }
    val handled = remember { AtomicBoolean(false) }
    val previewView = remember { PreviewView(context) }
    var cameraError by remember { mutableStateOf<String?>(null) }

    DisposableEffect(lifecycleOwner) {
        var disposed = false
        var boundProvider: ProcessCameraProvider? = null
        val cameraProviderFuture = ProcessCameraProvider.getInstance(context)
        val mainExecutor = ContextCompat.getMainExecutor(context)

        cameraProviderFuture.addListener(
            {
                if (disposed) return@addListener
                try {
                    val cameraProvider = cameraProviderFuture.get()
                    if (disposed) {
                        cameraProvider.unbindAll()
                        return@addListener
                    }
                    boundProvider = cameraProvider

                    val preview = Preview.Builder().build().also {
                        it.surfaceProvider = previewView.surfaceProvider
                    }

                    val imageAnalysis = ImageAnalysis.Builder()
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()

                    imageAnalysis.setAnalyzer(analyzerExecutor) { imageProxy ->
                        try {
                            if (handled.get()) return@setAnalyzer
                            val luma = extractLumaBytes(imageProxy)
                            val decoded = QrCodeUtils.decodeQrFromLuma(
                                yData = luma,
                                dataWidth = imageProxy.width,
                                dataHeight = imageProxy.height,
                            )
                            val trimmed = decoded?.trim()
                            if (!trimmed.isNullOrEmpty() &&
                                trimmed.startsWith("sshtun://", ignoreCase = true) &&
                                handled.compareAndSet(false, true)
                            ) {
                                mainExecutor.execute {
                                    onQrScanned(trimmed)
                                }
                            }
                        } finally {
                            imageProxy.close()
                        }
                    }

                    cameraProvider.unbindAll()
                    cameraProvider.bindToLifecycle(
                        lifecycleOwner,
                        CameraSelector.DEFAULT_BACK_CAMERA,
                        preview,
                        imageAnalysis,
                    )
                } catch (e: Exception) {
                    cameraError = e.message ?: "Unable to start camera preview"
                }
            },
            mainExecutor,
        )

        onDispose {
            disposed = true
            runCatching { boundProvider?.unbindAll() }
            analyzerExecutor.shutdown()
        }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Surface(
            color = TunSshColors.BgSurface,
            shape = RoundedCornerShape(16.dp),
            border = BorderStroke(1.dp, TunSshColors.BorderSubtle),
            modifier = Modifier
                .fillMaxWidth()
                .statusBarsPadding()
                .navigationBarsPadding()
                .padding(horizontal = 16.dp),
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Scan QR Code",
                            style = MaterialTheme.typography.titleMedium,
                            color = TunSshColors.TextPrimary,
                        )
                        Text(
                            text = "Point camera at a desktop tunssh QR code",
                            style = MaterialTheme.typography.bodySmall,
                            color = TunSshColors.TextMuted,
                        )
                    }
                    IconButton(onClick = onDismiss) {
                        Icon(
                            imageVector = Icons.Rounded.Close,
                            contentDescription = "Close scanner",
                            tint = TunSshColors.TextMuted,
                        )
                    }
                }

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(340.dp)
                        .clip(RoundedCornerShape(12.dp)),
                    contentAlignment = Alignment.Center,
                ) {
                    if (cameraError != null) {
                        Text(
                            text = cameraError!!,
                            style = MaterialTheme.typography.bodySmall,
                            color = TunSshColors.ErrorRed,
                            modifier = Modifier.padding(16.dp),
                        )
                    } else {
                        AndroidView(
                            factory = { previewView },
                            modifier = Modifier.fillMaxSize(),
                        )
                    }
                }
            }
        }
    }
}

private fun extractLumaBytes(imageProxy: ImageProxy): ByteArray {
    val plane = imageProxy.planes[0]
    val width = imageProxy.width
    val height = imageProxy.height
    val rowStride = plane.rowStride
    val pixelStride = plane.pixelStride
    val buffer = plane.buffer
    buffer.rewind()

    val output = ByteArray(width * height)
    if (pixelStride == 1 && rowStride == width) {
        val count = minOf(output.size, buffer.remaining())
        buffer.get(output, 0, count)
        return output
    }

    val rowBuffer = ByteArray(rowStride)
    for (row in 0 until height) {
        val remaining = buffer.remaining()
        if (remaining <= 0) break
        val toRead = minOf(rowStride, remaining)
        buffer.get(rowBuffer, 0, toRead)
        val outOffset = row * width
        if (pixelStride == 1) {
            val copyLen = minOf(width, toRead)
            System.arraycopy(rowBuffer, 0, output, outOffset, copyLen)
        } else {
            for (col in 0 until width) {
                val srcIdx = col * pixelStride
                if (srcIdx >= toRead) break
                output[outOffset + col] = rowBuffer[srcIdx]
            }
        }
    }
    return output
}
