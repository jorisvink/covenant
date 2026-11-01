package se.sanctorum.reliquary

/**
 * The C core, see include/reliquary.h and src/platform_android.c.
 *
 * We keep one context for the whole app. Calls on it must not overlap,
 * so every call goes through here, synchronised, and reads the error of
 * the context right after a call failed. Every call that takes the vault
 * key copies it, the caller wipes its own.
 */
object Core {
    /** A call into the C library failed, code is one of the COVENANT_ERROR_* values. */
    class Failure(val code: Int) : Exception("covenant core error $code")

    private val ctx: Long

    init {
        System.loadLibrary("covenant")
        ctx = ctxAlloc()
        check(ctx != 0L) { "the reliquary core failed to start" }
    }

    @Synchronized
    fun keksGenerate(vk: ByteArray, flock: Long): ByteArray =
        keksGenerate(ctx, vk, flock) ?: fail()

    @Synchronized
    fun keksRenew(vk: ByteArray, sealed: ByteArray, kek: Int): ByteArray =
        keksRenew(ctx, vk, sealed, kek) ?: fail()

    const val SEALED_V1_LEN = 72 + 255 * 32 + 16

    @Synchronized
    fun keksUpgrade(vk: ByteArray, sealed: ByteArray): ByteArray =
        keksUpgrade(ctx, vk, sealed) ?: fail()

    @Synchronized
    fun keksCheck(vk: ByteArray, sealed: ByteArray): Boolean =
        keksCheck(ctx, vk, sealed)

    /** The flock and when the KEKs were made, null if these are no sealed KEKs. */
    @Synchronized
    fun keksInfo(sealed: ByteArray): LongArray? = keksInfo(ctx, sealed)

    /** meta gets the generation and the expiry day. */
    @Synchronized
    fun ambryBundle(vk: ByteArray, sealed: ByteArray, days: Int, meta: IntArray): ByteArray =
        ambryBundle(ctx, vk, sealed, days, meta) ?: fail()

    /** The handle (4 bytes, big endian) followed by the public key. */
    @Synchronized
    fun coskNew(): ByteArray = coskNew(ctx) ?: fail()

    @Synchronized
    fun coskDrop(handle: Int) {
        coskDrop(ctx, handle)
    }

    /** The QR modules, side * side bytes. */
    @Synchronized
    fun provision(
        vk: ByteArray,
        sealed: ByteArray,
        kek: Int,
        handle: Int,
        secret: String,
        config: String
    ): ByteArray = provision(ctx, vk, sealed, kek, handle, secret, config) ?: fail()

    @Synchronized
    fun provisionConfig(
        vk: ByteArray,
        sealed: ByteArray,
        kek: Int,
        handle: Int,
        secret: String,
        config: String
    ): ByteArray = provisionConfig(ctx, vk, sealed, kek, handle, secret, config) ?: fail()

    /** The recovery key followed by its recipient. */
    @Synchronized
    fun backupKeygen(vk: ByteArray): ByteArray = backupKeygen(ctx, vk) ?: fail()

    @Synchronized
    fun backupRecipient(vk: ByteArray, root: ByteArray): ByteArray =
        backupRecipient(ctx, vk, root) ?: fail()

    @Synchronized
    fun backupVerify(root: ByteArray, recipient: ByteArray): Boolean =
        backupVerify(ctx, root, recipient)

    @Synchronized
    fun backupSeal(vk: ByteArray, recipient: ByteArray, sealed: ByteArray): ByteArray =
        backupSeal(ctx, vk, recipient, sealed) ?: fail()

    @Synchronized
    fun backupRestore(vk: ByteArray, root: ByteArray, backup: ByteArray): ByteArray =
        backupRestore(ctx, vk, root, backup) ?: fail()

    /** The flock, made and created of a backup, null if this is no backup. */
    @Synchronized
    fun backupInfo(backup: ByteArray): LongArray? = backupInfo(ctx, backup)

    fun version(): String = coreVersion()

    private fun fail(): Nothing = throw Failure(lastError(ctx))

    @JvmStatic
    private external fun coreVersion(): String

    @JvmStatic
    private external fun ctxAlloc(): Long

    @JvmStatic
    private external fun ctxFree(ctx: Long)

    @JvmStatic
    private external fun lastError(ctx: Long): Int

    @JvmStatic
    private external fun keksGenerate(ctx: Long, vk: ByteArray, flock: Long): ByteArray?

    @JvmStatic
    private external fun keksRenew(ctx: Long, vk: ByteArray, sealed: ByteArray, kek: Int): ByteArray?

    @JvmStatic
    private external fun keksUpgrade(ctx: Long, vk: ByteArray, sealed: ByteArray): ByteArray?

    @JvmStatic
    private external fun keksCheck(ctx: Long, vk: ByteArray, sealed: ByteArray): Boolean

    @JvmStatic
    private external fun keksInfo(ctx: Long, sealed: ByteArray): LongArray?

    @JvmStatic
    private external fun ambryBundle(
        ctx: Long, vk: ByteArray, sealed: ByteArray, days: Int, meta: IntArray
    ): ByteArray?

    @JvmStatic
    private external fun coskNew(ctx: Long): ByteArray?

    @JvmStatic
    private external fun coskDrop(ctx: Long, handle: Int): Boolean

    @JvmStatic
    private external fun provision(
        ctx: Long,
        vk: ByteArray,
        sealed: ByteArray,
        kek: Int,
        handle: Int,
        secret: String,
        config: String
    ): ByteArray?

    @JvmStatic
    private external fun provisionConfig(
        ctx: Long,
        vk: ByteArray,
        sealed: ByteArray,
        kek: Int,
        handle: Int,
        secret: String,
        config: String
    ): ByteArray?

    @JvmStatic
    private external fun backupKeygen(ctx: Long, vk: ByteArray): ByteArray?

    @JvmStatic
    private external fun backupRecipient(ctx: Long, vk: ByteArray, root: ByteArray): ByteArray?

    @JvmStatic
    private external fun backupVerify(ctx: Long, root: ByteArray, recipient: ByteArray): Boolean

    @JvmStatic
    private external fun backupSeal(
        ctx: Long, vk: ByteArray, recipient: ByteArray, sealed: ByteArray
    ): ByteArray?

    @JvmStatic
    private external fun backupRestore(
        ctx: Long, vk: ByteArray, root: ByteArray, backup: ByteArray
    ): ByteArray?

    @JvmStatic
    private external fun backupInfo(ctx: Long, backup: ByteArray): LongArray?
}
