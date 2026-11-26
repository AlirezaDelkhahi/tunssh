package dev.tunssh.android.ui

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.nio.charset.StandardCharsets

object QrCodeUtils {

    const val MAX_QR_BYTES = 2200

    private const val QR_DARK_ARGB = 0xFF0B0F17.toInt()
    private const val QR_LIGHT_ARGB = 0xFFFFFFFF.toInt()

    fun encodeQrBitmap(content: String, sizePx: Int = 512): Bitmap? {
        if (content.isBlank() || sizePx <= 0) {
            return null
        }
        val utf8Bytes = content.toByteArray(StandardCharsets.UTF_8)
        if (utf8Bytes.size > MAX_QR_BYTES) {
            return null
        }

        val hints = mapOf(
            EncodeHintType.CHARACTER_SET to "UTF-8",
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
            EncodeHintType.MARGIN to 2,
        )

        val matrix = runCatching {
            QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
        }.getOrNull() ?: return null

        val width = matrix.width
        val height = matrix.height
        val pixels = IntArray(width * height)
        for (y in 0 until height) {
            val rowOffset = y * width
            for (x in 0 until width) {
                pixels[rowOffset + x] = if (matrix.get(x, y)) QR_DARK_ARGB else QR_LIGHT_ARGB
            }
        }

        return Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888).apply {
            setPixels(pixels, 0, width, 0, 0, width, height)
        }
    }

    fun decodeQrFromLuma(yData: ByteArray, dataWidth: Int, dataHeight: Int): String? {
        if (dataWidth <= 0 || dataHeight <= 0 || yData.size < dataWidth * dataHeight) {
            return null
        }
        val source = PlanarYUVLuminanceSource(
            yData,
            dataWidth,
            dataHeight,
            0,
            0,
            dataWidth,
            dataHeight,
            false,
        )
        return decodeLuminanceSource(source)
    }

    fun decodeQrFromBitmap(bitmap: Bitmap): String? {
        val width = bitmap.width
        val height = bitmap.height
        if (width <= 0 || height <= 0) {
            return null
        }
        val pixels = IntArray(width * height)
        bitmap.getPixels(pixels, 0, width, 0, 0, width, height)
        val source = RGBLuminanceSource(width, height, pixels)
        return decodeLuminanceSource(source)
    }

    private fun decodeLuminanceSource(source: LuminanceSource): String? {
        val hints = mapOf(
            DecodeHintType.CHARACTER_SET to "UTF-8",
            DecodeHintType.TRY_HARDER to true,
        )
        val reader = QRCodeReader()
        return try {
            try {
                reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
            } catch (_: NotFoundException) {
                reader.reset()
                reader.decode(BinaryBitmap(HybridBinarizer(source.invert())), hints).text
            }
        } catch (_: ReaderException) {
            null
        } finally {
            reader.reset()
        }
    }
}
