package se.sanctorum.reliquary

import android.app.Activity
import android.content.Context
import android.net.Uri
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.security.InvalidAlgorithmParameterException
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * The vault: the KEKs of each flock sealed by the C library under the
 * vault key, and the vault key itself wrapped by an AES-256-GCM key
 * that lives in StrongBox (or the TEE when there is none) and that can
 * only be used right after the user authenticated with biometrics or
 * the device credential, for every single use. The key is bound to this
 * device, requires it to be unlocked and is gone when the screen lock
 * goes.
 *
 * Next to the KEKs we keep the backup recipient and the latest backup of
 * each flock, "pending" until it is written to the backup folder.
 */
class Vault(context: Context) {
    class Cancelled : Exception("Your KEKs were not unlocked.")
    class Invalidated : Exception(
        "The screen lock was changed, so the KEKs on this phone can no longer be opened."
    )
    class NoLock : Exception("Set up a screen lock (PIN, pattern or password) first, it protects your KEKs.")
    class Missing(flock: String) : Exception("The KEKs of this flock are not on this phone.")

    private val dir = File(context.noBackupFilesDir, "vault").apply { mkdirs() }
    private val keyFile = File(dir, "vault.key")
    private val recipientFile = File(dir, "backup.recipient")
    private val folderFile = File(dir, "backup.folder")
    private val app = context.applicationContext
    private val random = SecureRandom()

    fun info(): JSONObject {
        val flocks = JSONArray()

        dir.listFiles { f -> f.name.endsWith(KEKS) }?.sortedBy { it.name }?.forEach { f ->
            val info = Core.keksInfo(f.readBytes()) ?: return@forEach
            flocks.put(
                JSONObject()
                    .put("flock", "%016x".format(info[0]))
                    .put("created", info[1])
                    .put("backup", backupState("%016x".format(info[0])))
            )
        }

        val folder = folder()
        val backup = JSONObject()
            .put("key", recipientFile.exists())
            .put("folder", folder?.let { BackupFolder.name(app, it) ?: "Chosen folder" } ?: JSONObject.NULL)

        val key = if (keyFile.exists()) key() else null

        return JSONObject()
            .put("ready", key != null)
            .put("invalidated", key != null && invalidated(key))
            .put("hardware", key?.let { level(it) } ?: "none")
            .put("auth", "Fingerprint, face or the device PIN, every time")
            .put("flocks", flocks)
            .put("backup", backup)
    }

    fun sealed(flock: String): ByteArray {
        val file = flockFile(flock)
        if (!file.exists()) throw Missing(flock)
        return file.readBytes()
    }

    fun has(flock: String) = flockFile(flock).exists()

    fun store(flock: String, sealed: ByteArray) = write(flockFile(flock), sealed)

    fun remove(flock: String) {
        wipe(flockFile(flock))
        wipe(backupFile(flock))
        wipe(exportedFile(flock))
    }

    fun flocks(): List<String> =
        dir.listFiles { f -> f.name.endsWith(KEKS) }?.map { it.name.removeSuffix(KEKS) }?.sorted() ?: emptyList()

    fun recipient(): ByteArray? = if (recipientFile.exists()) recipientFile.readBytes() else null

    fun storeRecipient(recipient: ByteArray) = write(recipientFile, recipient)

    fun folder(): Uri? = if (folderFile.exists()) Uri.parse(folderFile.readText()) else null

    fun storeFolder(tree: Uri) = write(folderFile, tree.toString().toByteArray())

    fun storeBackup(flock: String, backup: ByteArray, exported: Boolean = false) {
        wipe(exportedFile(flock))
        write(backupFile(flock), backup)
        if (exported) exported(flock)
    }

    fun dropBackup(flock: String) {
        wipe(backupFile(flock))
        wipe(exportedFile(flock))
    }

    fun exported(flock: String) = write(exportedFile(flock), ByteArray(0))

    /** The backups not written to the backup folder yet. */
    fun pending(): List<Pair<String, ByteArray>> =
        flocks().filter { backupState(it) == "pending" }.map { it to backupFile(it).readBytes() }

    private fun backupState(flock: String): String =
        when {
            !backupFile(flock).exists() -> "none"
            exportedFile(flock).exists() -> "exported"
            else -> "pending"
        }

    fun wipeAll() {
        dir.listFiles()?.forEach { wipe(it) }
        KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(ALIAS)
    }

    /**
     * Ask the user to authenticate and hand over the vault key, making
     * the vault first when create is set and there is none. The caller
     * must wipe the key. Runs the prompt on the main thread.
     *
     * The hardware key was made with an authentication timeout of 0,
     * which means it cannot be used on its own at all: every operation
     * needs a fresh authentication bound to that exact operation. So we
     * set up the Cipher first (init only picks the key and the nonce, it
     * needs no authentication) and hand it to the BiometricPrompt as its
     * CryptoObject. Only once the user authenticated does the keystore
     * allow that one Cipher to do its doFinal(), any other use of the key
     * keeps failing.
     *
     * There are two flows through here:
     *
     *  - creating: there is no vault.key yet, we make a new hardware key
     *    and init the Cipher for ENCRYPT, the keystore picks the nonce.
     *    After the prompt we make 32 random bytes, the vault key, encrypt
     *    them and store nonce || ciphertext || tag as vault.key. The
     *    plaintext vault key goes straight to the caller.
     *
     *  - opening: vault.key exists, we init the Cipher for DECRYPT with
     *    the nonce from the start of the file. After the prompt doFinal()
     *    decrypts and authenticates the rest, which is the vault key.
     *
     * Either way the AAD binds the wrapped key to what it is for, and the
     * vault key itself never touches the disk in the clear.
     */
    fun unlock(activity: Activity, reason: String, create: Boolean, done: (ByteArray?, Exception?) -> Unit) {
        val creating = !keyFile.exists()
        val sealed: ByteArray?
        val cipher = Cipher.getInstance(GCM)

        try {
            if (creating) {
                if (!create) throw IllegalStateException("There is no vault on this phone yet.")

                cipher.init(Cipher.ENCRYPT_MODE, generate())
                sealed = null
            } else {
                sealed = keyFile.readBytes()
                require(sealed.size == NONCE + VK_LEN + TAG / 8) { "The vault key file is damaged." }
                cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG, sealed, 0, NONCE))
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            done(null, Invalidated())
            return
        } catch (e: Exception) {
            done(null, e)
            return
        }

        val prompt = BiometricPrompt.Builder(activity)
            .setTitle(if (creating) "Create your key vault" else "Unlock your KEKs")
            .setSubtitle(reason)
            .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL)
            .setConfirmationRequired(false)
            .build()

        prompt.authenticate(
            BiometricPrompt.CryptoObject(cipher),
            CancellationSignal(),
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    // The Cipher the user just authorised, good for one doFinal().
                    val unlocked = result.cryptoObject?.cipher ?: cipher

                    try {
                        unlocked.updateAAD(AAD)

                        if (sealed == null) {
                            // Creating: a new random vault key, wrapped
                            // under the hardware key as nonce || ct || tag.
                            val vk = ByteArray(VK_LEN).also { random.nextBytes(it) }
                            val wrapped = unlocked.iv + unlocked.doFinal(vk)
                            write(keyFile, wrapped)
                            done(vk, null)
                        } else {
                            // Opening: skip the nonce, decrypt and verify
                            // the tag, what comes out is the vault key.
                            done(unlocked.doFinal(sealed, NONCE, sealed.size - NONCE), null)
                        }
                    } catch (e: Exception) {
                        done(null, e)
                    }
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    when (code) {
                        BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED,
                        BiometricPrompt.BIOMETRIC_ERROR_CANCELED -> done(null, Cancelled())
                        BiometricPrompt.BIOMETRIC_ERROR_NO_DEVICE_CREDENTIAL -> done(null, NoLock())
                        else -> done(null, Exception(message.toString()))
                    }
                }
            }
        )
    }

    private fun key(): SecretKey? {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        return (store.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
    }

    /** A fresh hardware key, preferring StrongBox over the TEE. */
    private fun generate(): SecretKey {
        KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(ALIAS)

        fun make(strongbox: Boolean): SecretKey =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).run {
                init(
                    KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setKeySize(256)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setUserAuthenticationRequired(true)
                        .setUserAuthenticationParameters(
                            0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                        )
                        // A new fingerprint must not destroy the KEKs, the
                        // device credential opens the vault anyway.
                        .setInvalidatedByBiometricEnrollment(false)
                        .setUnlockedDeviceRequired(true)
                        .setIsStrongBoxBacked(strongbox)
                        .build()
                )
                generateKey()
            }

        try {
            return try {
                make(true)
            } catch (e: StrongBoxUnavailableException) {
                make(false)
            }
        } catch (e: InvalidAlgorithmParameterException) {
            throw NoLock()
        } catch (e: IllegalStateException) {
            throw NoLock()
        }
    }

    private fun invalidated(key: SecretKey): Boolean =
        try {
            Cipher.getInstance(GCM).init(Cipher.ENCRYPT_MODE, key)
            false
        } catch (e: KeyPermanentlyInvalidatedException) {
            true
        } catch (e: Exception) {
            false
        }

    private fun level(key: SecretKey): String {
        val info = SecretKeyFactory.getInstance(key.algorithm, KEYSTORE)
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> "tee"
                else -> "software"
            }
        }

        @Suppress("DEPRECATION")
        return if (info.isInsideSecureHardware) "tee" else "software"
    }

    private fun flockFile(flock: String): File {
        require(flock.matches(Regex("[0-9a-f]{16}"))) { "invalid flock $flock" }
        return File(dir, flock + KEKS)
    }

    private fun backupFile(flock: String) = File(dir, flockFile(flock).name.removeSuffix(KEKS) + BACKUP)

    private fun exportedFile(flock: String) = File(dir, flockFile(flock).name.removeSuffix(KEKS) + EXPORTED)

    private fun write(file: File, data: ByteArray) {
        val temp = File(file.parentFile, file.name + ".tmp")

        FileOutputStream(temp).use {
            it.write(data)
            it.fd.sync()
        }

        if (!temp.renameTo(file)) throw IllegalStateException("failed to write ${file.name}")
    }

    private fun wipe(file: File) {
        if (!file.exists()) return

        FileOutputStream(file).use {
            it.write(ByteArray(file.length().toInt()))
            it.fd.sync()
        }

        file.delete()
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "se.sanctorum.reliquary.vault"
        const val GCM = "AES/GCM/NoPadding"
        const val KEKS = ".keks"
        const val BACKUP = ".backup"
        const val EXPORTED = ".exported"
        const val NONCE = 12
        const val TAG = 128
        const val VK_LEN = 32
        val AAD = "reliquary vault key 1".toByteArray()
    }
}
