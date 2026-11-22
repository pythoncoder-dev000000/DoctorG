package com.python.doctorg.core.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.core.content.edit
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.InputStream
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.pow

@Singleton
class CryptoManager @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val keyStoreAlias = "doctorg_master_aes256_gcm"
    private val prefsName = "doctorg_keystore_meta"
    private val secureRandom = SecureRandom()

    private fun getOrCreateKey(): SecretKey {
        return runCatching {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val existing = keyStore.getKey(keyStoreAlias, null) as? SecretKey
            if (existing != null) return existing

            val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            val spec = KeyGenParameterSpec.Builder(
                keyStoreAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
            keyGen.init(spec)
            keyGen.generateKey()
        }.getOrElse {
            if (Build.FINGERPRINT.equals("robolectric", ignoreCase = true)) {
                val fallbackBytes = sha256Bytes("doctorg-test-fallback-${context.packageName}".toByteArray())
                SecretKeySpec(fallbackBytes, "AES")
            } else {
                val prefs = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
                val existingB64 = prefs.getString("fallback_aes_key", null)
                val raw = existingB64?.let { runCatching { Base64.decode(it, Base64.NO_WRAP) }.getOrNull() }
                    ?.takeIf { it.size == 32 }
                    ?: ByteArray(32).also { bytes ->
                        secureRandom.nextBytes(bytes)
                        prefs.edit { putString("fallback_aes_key", Base64.encodeToString(bytes, Base64.NO_WRAP)) }
                    }
                SecretKeySpec(raw, "AES")
            }
        }
    }

    fun encryptBytes(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val iv = cipher.iv
        val cipherText = cipher.doFinal(plain)
        return ByteBuffer.allocate(4 + iv.size + cipherText.size)
            .putInt(iv.size)
            .put(iv)
            .put(cipherText)
            .array()
    }

    fun decryptBytes(blob: ByteArray): ByteArray {
        val buffer = ByteBuffer.wrap(blob)
        val ivLen = buffer.int
        require(ivLen in 12..32) { "Invalid IV length" }
        val iv = ByteArray(ivLen)
        buffer.get(iv)
        val cipherText = ByteArray(buffer.remaining())
        buffer.get(cipherText)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
        return cipher.doFinal(cipherText)
    }

    fun encryptString(plainText: String): String {
        if (plainText.isEmpty()) return ""
        return Base64.encodeToString(encryptBytes(plainText.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
    }

    fun decryptString(encoded: String): String {
        if (encoded.isEmpty()) return ""
        return runCatching {
            String(decryptBytes(Base64.decode(encoded, Base64.NO_WRAP)), Charsets.UTF_8)
        }.getOrDefault("")
    }

    /**
     * Generates and persists a random 32-byte passphrase wrapped by Android Keystore
     * for opening the SQLCipher encrypted Vault Room database.
     */
    fun getOrCreateVaultPassphrase(): ByteArray {
        val prefs = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
        val stored = prefs.getString("vault_key_wrapped", null)
        if (!stored.isNullOrBlank()) {
            val unwrapped = runCatching { decryptBytes(Base64.decode(stored, Base64.NO_WRAP)) }.getOrNull()
            if (unwrapped != null && unwrapped.size == 32) return unwrapped
        }
        val raw = ByteArray(32).also { secureRandom.nextBytes(it) }
        val wrapped = Base64.encodeToString(encryptBytes(raw), Base64.NO_WRAP)
        prefs.edit { putString("vault_key_wrapped", wrapped) }
        return raw
    }

    fun encryptWithPassword(plain: ByteArray, password: String): ByteArray {
        val salt = ByteArray(16).also { secureRandom.nextBytes(it) }
        val keySpec = PBEKeySpec(password.toCharArray(), salt, 65_536, 256)
        val secret = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(keySpec).encoded
        try {
            val aesKey = SecretKeySpec(secret, "AES")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, aesKey)
            val iv = cipher.iv
            val cipherText = cipher.doFinal(plain)
            return ByteBuffer.allocate(4 + salt.size + 4 + iv.size + cipherText.size)
                .putInt(salt.size).put(salt)
                .putInt(iv.size).put(iv)
                .put(cipherText)
                .array()
        } finally {
            keySpec.clearPassword()
            secret.fill(0)
        }
    }

    fun decryptWithPassword(blob: ByteArray, password: String): ByteArray {
        require(blob.size >= 36) { "Corrupted encrypted backup" }
        val buf = ByteBuffer.wrap(blob)
        val saltLen = buf.int
        require(saltLen in 8..64 && buf.remaining() >= saltLen + 4) { "Invalid salt length" }
        val salt = ByteArray(saltLen).also { buf.get(it) }
        val ivLen = buf.int
        require(ivLen in 12..32 && buf.remaining() >= ivLen + 16) { "Invalid IV length" }
        val iv = ByteArray(ivLen).also { buf.get(it) }
        val cipherText = ByteArray(buf.remaining()).also { buf.get(it) }
        val keySpec = PBEKeySpec(password.toCharArray(), salt, 65_536, 256)
        val secret = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(keySpec).encoded
        try {
            val aesKey = SecretKeySpec(secret, "AES")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(128, iv))
            return cipher.doFinal(cipherText)
        } finally {
            keySpec.clearPassword()
            secret.fill(0)
        }
    }

    fun hashSecretPin(pin: String): String {
        val salt = ByteArray(16).also { secureRandom.nextBytes(it) }
        val spec = PBEKeySpec(pin.toCharArray(), salt, 65_536, 256)
        val hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        return Base64.encodeToString(salt, Base64.NO_WRAP) + ":" + Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    fun verifySecretPin(pin: String, stored: String): Boolean {
        val parts = stored.split(":")
        if (parts.size != 2) return false
        val salt = runCatching { Base64.decode(parts[0], Base64.NO_WRAP) }.getOrNull() ?: return false
        val expected = runCatching { Base64.decode(parts[1], Base64.NO_WRAP) }.getOrNull() ?: return false
        val spec = PBEKeySpec(pin.toCharArray(), salt, 65_536, 256)
        val actual = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        return MessageDigest.isEqual(expected, actual)
    }

    /**
     * Streaming SHA-256 with bounded 8KB buffer on Dispatchers.IO so low-RAM devices never OOM.
     */
    suspend fun sha256File(file: File): String = withContext(Dispatchers.IO) {
        file.inputStream().use { sha256Stream(it) }
    }

    fun sha256Stream(input: InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(8 * 1024)
        var read = input.read(buffer)
        while (read != -1) {
            digest.update(buffer, 0, read)
            read = input.read(buffer)
        }
        return digest.digest().toHexString()
    }

    fun sha256Bytes(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    fun sha256Hex(text: String): String =
        sha256Bytes(text.toByteArray(Charsets.UTF_8)).toHexString()

    fun sha1HexUpper(text: String): String =
        MessageDigest.getInstance("SHA-1").digest(text.toByteArray(Charsets.UTF_8))
            .toHexString().uppercase()

    fun generateStrongPassword(
        length: Int = 18,
        includeSymbols: Boolean = true,
        includeDigits: Boolean = true
    ): String {
        val lower = "abcdefghijkmnopqrstuvwxyz"
        val upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
        val digits = "23456789"
        val symbols = "!@#$%^&*()-_=+[]{}"
        val pool = buildString {
            append(lower)
            append(upper)
            if (includeDigits) append(digits)
            if (includeSymbols) append(symbols)
        }
        val chars = mutableListOf(
            lower[secureRandom.nextInt(lower.length)],
            upper[secureRandom.nextInt(upper.length)]
        )
        if (includeDigits) chars.add(digits[secureRandom.nextInt(digits.length)])
        if (includeSymbols) chars.add(symbols[secureRandom.nextInt(symbols.length)])
        while (chars.size < length.coerceAtLeast(8)) {
            chars.add(pool[secureRandom.nextInt(pool.length)])
        }
        chars.shuffle(secureRandom)
        return chars.joinToString("")
    }

    fun evaluatePasswordStrength(password: String): Int {
        if (password.isEmpty()) return 0
        var score = 0
        if (password.length >= 8) score += 20
        if (password.length >= 12) score += 20
        if (password.length >= 16) score += 10
        if (password.any { it.isLowerCase() }) score += 12
        if (password.any { it.isUpperCase() }) score += 13
        if (password.any { it.isDigit() }) score += 12
        if (password.any { !it.isLetterOrDigit() }) score += 13
        val common = setOf("password", "123456", "qwerty", "admin", "12345678", "india123")
        if (password.lowercase() in common) score = minOf(score, 15)
        return score.coerceIn(0, 100)
    }

    /**
     * RFC 6238 TOTP generator (HMAC-SHA1, 30s period, 6 digits).
     */
    fun generateTotp(
        base32Secret: String,
        timeMillis: Long = System.currentTimeMillis(),
        periodSeconds: Int = 30,
        digits: Int = 6
    ): String {
        val keyBytes = decodeBase32(base32Secret)
        if (keyBytes.isEmpty()) return "0".repeat(digits)
        val counter = (timeMillis / 1000L) / periodSeconds
        val data = ByteBuffer.allocate(8).putLong(counter).array()
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(keyBytes, "HmacSHA1"))
        val hash = mac.doFinal(data)
        val offset = hash[hash.size - 1].toInt() and 0x0F
        val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)
        val otp = binary % 10.0.pow(digits).toInt()
        return otp.toString().padStart(digits, '0')
    }

    fun totpRemainingSeconds(timeMillis: Long = System.currentTimeMillis(), periodSeconds: Int = 30): Int {
        val elapsed = ((timeMillis / 1000L) % periodSeconds).toInt()
        return periodSeconds - elapsed
    }

    fun decodeBase32(input: String): ByteArray {
        val cleaned = input.uppercase().replace("=", "").replace(" ", "").replace("-", "")
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val out = ArrayList<Byte>(cleaned.length * 5 / 8)
        var buffer = 0
        var bitsLeft = 0
        for (ch in cleaned) {
            val value = alphabet.indexOf(ch)
            if (value < 0) continue
            buffer = (buffer shl 5) or value
            bitsLeft += 5
            if (bitsLeft >= 8) {
                bitsLeft -= 8
                out.add(((buffer shr bitsLeft) and 0xFF).toByte())
            }
        }
        return out.toByteArray()
    }

    private fun ByteArray.toHexString(): String =
        joinToString(separator = "") { b -> "%02x".format(b) }
}
