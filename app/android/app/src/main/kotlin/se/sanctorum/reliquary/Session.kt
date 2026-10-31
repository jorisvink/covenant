package se.sanctorum.reliquary

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The API session (the token), encrypted under a hardware key that needs
 * the device unlocked but no prompt, so the app can list flocks freely.
 * The KEKs are in the Vault, not here.
 */
class Session(context: Context) {
    private val file = File(context.noBackupFilesDir, "session")

    fun load(): String? {
        if (!file.exists()) return null

        val sealed = file.readBytes()
        val cipher = Cipher.getInstance(GCM)

        return try {
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG, sealed, 0, NONCE))
            cipher.updateAAD(AAD)
            String(cipher.doFinal(sealed, NONCE, sealed.size - NONCE))
        } catch (e: Exception) {
            null
        }
    }

    fun save(json: String) {
        val cipher = Cipher.getInstance(GCM)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(AAD)

        val sealed = cipher.iv + cipher.doFinal(json.toByteArray())
        val temp = File(file.parentFile, file.name + ".tmp")

        FileOutputStream(temp).use {
            it.write(sealed)
            it.fd.sync()
        }

        if (!temp.renameTo(file)) throw IllegalStateException("failed to save the session")
    }

    fun clear() {
        if (file.exists()) {
            FileOutputStream(file).use { it.write(ByteArray(file.length().toInt())) }
            file.delete()
        }
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }

        (store.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        fun make(strongbox: Boolean): SecretKey =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).run {
                init(
                    KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setKeySize(256)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setUnlockedDeviceRequired(true)
                        .setIsStrongBoxBacked(strongbox)
                        .build()
                )
                generateKey()
            }

        return try {
            make(true)
        } catch (e: StrongBoxUnavailableException) {
            make(false)
        }
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "se.sanctorum.reliquary.session"
        const val GCM = "AES/GCM/NoPadding"
        const val NONCE = 12
        const val TAG = 128
        val AAD = "reliquary session 1".toByteArray()
    }
}
