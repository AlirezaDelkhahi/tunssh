package dev.tunssh.android.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import dev.tunssh.android.model.ProfileSecrets
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stores per-profile credentials encrypted with an AndroidKeyStore AES-256-GCM key.
 * Secrets are never written to SharedPreferences or profiles.json.
 */
class KeystoreSecretStore(context: Context) {

    private val secretsDir = File(context.filesDir, SECRETS_DIR_NAME)
    private val lock = Any()

    fun saveSecrets(profileId: String, secrets: ProfileSecrets) {
        val safeId = validateProfileId(profileId)
        synchronized(lock) {
            if (!secretsDir.exists() && !secretsDir.mkdirs()) {
                throw IllegalStateException("Failed to create secrets directory")
            }

            val secretKey = getOrCreateMasterKey()
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            cipher.updateAAD(buildAad(safeId))

            val iv = cipher.iv
            require(iv.size == GCM_IV_BYTES) { "Unexpected GCM IV length: ${iv.size}" }

            val plaintext = secrets.toJsonString().toByteArray(StandardCharsets.UTF_8)
            val ciphertext = try {
                cipher.doFinal(plaintext)
            } finally {
                plaintext.fill(0)
            }

            val envelope = JSONObject().apply {
                put("v", FORMAT_VERSION)
                put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
                put("ct", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            }.toString()

            writeAtomic(secretFileFor(safeId), envelope.toByteArray(StandardCharsets.UTF_8))
        }
    }

    fun loadSecrets(profileId: String): ProfileSecrets? {
        val safeId = validateProfileId(profileId)
        synchronized(lock) {
            val file = secretFileFor(safeId)
            if (!file.exists()) {
                return null
            }

            val raw = file.readText(StandardCharsets.UTF_8)
            val envelope = JSONObject(raw)
            val version = envelope.optInt("v", 0)
            if (version != FORMAT_VERSION) {
                throw IllegalStateException("Unsupported secret envelope version: $version")
            }
            val iv = Base64.decode(envelope.getString("iv"), Base64.NO_WRAP)
            val ciphertext = Base64.decode(envelope.getString("ct"), Base64.NO_WRAP)

            val secretKey = getOrCreateMasterKey()
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.updateAAD(buildAad(safeId))

            val plaintext = cipher.doFinal(ciphertext)
            return try {
                ProfileSecrets.fromJsonString(String(plaintext, StandardCharsets.UTF_8))
            } finally {
                plaintext.fill(0)
            }
        }
    }

    fun deleteSecrets(profileId: String) {
        val safeId = validateProfileId(profileId)
        synchronized(lock) {
            val file = secretFileFor(safeId)
            if (file.exists()) {
                file.delete()
            }
            val tmp = File(secretsDir, "$safeId.bin.tmp")
            if (tmp.exists()) {
                tmp.delete()
            }
        }
    }

    private fun secretFileFor(safeId: String): File = File(secretsDir, "$safeId.bin")

    private fun buildAad(safeId: String): ByteArray =
        "$AAD_PREFIX$safeId".toByteArray(StandardCharsets.UTF_8)

    private fun getOrCreateMasterKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = keyStore.getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) {
            return existing
        }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE,
        )
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(AES_KEY_BITS)
            .setRandomizedEncryptionRequired(true)
            .build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    private fun writeAtomic(target: File, bytes: ByteArray) {
        val temp = File(target.parentFile, "${target.name}.tmp")
        FileOutputStream(temp).use { fos ->
            fos.write(bytes)
            fos.flush()
            fos.fd.sync()
        }
        if (!temp.renameTo(target)) {
            temp.delete()
            throw IllegalStateException("Failed to atomically replace ${target.name}")
        }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "tunssh_secrets_master_v1"
        private const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val AES_KEY_BITS = 256
        private const val GCM_IV_BYTES = 12
        private const val GCM_TAG_BITS = 128
        private const val FORMAT_VERSION = 1
        private const val AAD_PREFIX = "tunssh:android:secrets:v1:"
        private const val SECRETS_DIR_NAME = "secrets"
        private val PROFILE_ID_REGEX = Regex("^[A-Za-z0-9_-]{1,128}$")

        fun validateProfileId(profileId: String): String {
            val trimmed = profileId.trim()
            require(PROFILE_ID_REGEX.matches(trimmed)) {
                "Invalid profile ID format"
            }
            return trimmed
        }
    }
}
