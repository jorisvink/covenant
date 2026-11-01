package se.sanctorum.reliquary

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * Answers the user interface on the se.sanctorum.reliquary/core channel.
 */
class MainActivity : FlutterActivity() {
    private lateinit var vault: Vault
    private lateinit var session: Session
    private var reminded = ""
    private var picking: MethodChannel.Result? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        // No screenshots, no recents thumbnail: QR codes carry keys. Debug
        // builds allow them so the app can be driven and looked at.
        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        super.onCreate(savedInstanceState)
        reminded(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        reminded(intent)
    }

    @Deprecated("FlutterActivity has no activity result API of its own")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode != PICK_FOLDER) return

        val result = picking ?: return
        val tree = data?.data
        picking = null

        if (resultCode != RESULT_OK || tree == null) {
            result.success(null)
            return
        }

        background(result) {
            BackupFolder.keep(this, tree)
            vault.storeFolder(tree)
            export()
            BackupFolder.name(this, tree) ?: "the chosen folder"
        }
    }

    private fun reminded(intent: Intent?) {
        reminded = intent?.getStringExtra(Reminders.EXTRA_FLOCK) ?: return
        intent.removeExtra(Reminders.EXTRA_FLOCK)
    }

    override fun configureFlutterEngine(engine: FlutterEngine) {
        super.configureFlutterEngine(engine)

        vault = Vault(this)
        session = Session(this)

        MethodChannel(engine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler(::handle)
    }

    private fun handle(call: MethodCall, result: MethodChannel.Result) {
        try {
            when (call.method) {
                "vault" -> background(result) { vault.info().toString() }
                "keksGenerate" -> {
                    val flock = flock(call.argument<String>("flock"))
                    val days = days(call)

                    withKey(result, "Set up the KEKs of your flock", create = true) { vk ->
                        val sealed = Core.keksGenerate(vk, flockId(flock))
                        val bundle = bundle(vk, sealed, days)

                        vault.store(flock, sealed)
                        backup(vk, flock, sealed)
                        bundle
                    }
                }
                "keksRenew" -> {
                    val flock = flock(call.argument<String>("flock"))
                    val kek = call.argument<Int>("kek") ?: 0
                    val days = days(call)
                    val sealed = vault.sealed(flock)

                    require(kek in 1..255) { "KEK IDs are 01 to ff." }

                    withKey(result, "Replace the KEK of a removed device", create = false) { vk ->
                        val renewed = Core.keksRenew(vk, upgraded(vk, flock, sealed), kek)
                        val bundle = bundle(vk, renewed, days)

                        vault.store(flock, renewed)
                        backup(vk, flock, renewed)
                        bundle
                    }
                }
                "bundle" -> {
                    val flock = flock(call.argument<String>("flock"))
                    val days = days(call)
                    val sealed = vault.sealed(flock)

                    withKey(result, "Make new encrypted secrets", create = false) { vk ->
                        bundle(vk, upgraded(vk, flock, sealed), days)
                    }
                }
                "keksDelete" -> {
                    vault.remove(flock(call.arguments as String?))
                    result.success("")
                }
                "backupKey" -> {
                    withKey(result, "Make a new recovery key", create = true) { vk ->
                        val both = Core.backupKeygen(vk)

                        try {
                            vault.storeRecipient(both.copyOfRange(ROOT_LEN, both.size))
                            backupAll(vk)
                            both.copyOfRange(0, ROOT_LEN)
                        } finally {
                            both.fill(0)
                        }
                    }
                }
                "backupAll" -> {
                    withKey(result, "Back up the KEKs of your flocks", create = false) { vk ->
                        backupAll(vk)
                        ""
                    }
                }
                "backupFolder" -> {
                    picking?.success(null)
                    picking = result
                    @Suppress("DEPRECATION")
                    startActivityForResult(BackupFolder.pick(), PICK_FOLDER)
                }
                "backupExport" -> background(result) { export() }
                "backupVerify" -> {
                    val root = call.arguments as ByteArray

                    background(result) {
                        try {
                            val recipient = vault.recipient()
                                ?: throw IllegalStateException("There is no recovery key on this phone.")
                            Core.backupVerify(root, recipient)
                        } finally {
                            root.fill(0)
                        }
                    }
                }
                "backupScan" -> background(result) { scan() }
                "backupRestore" -> {
                    val root = call.arguments as ByteArray

                    withKey(result, "Restore your KEKs", create = true) { vk ->
                        try {
                            restore(vk, root)
                        } finally {
                            root.fill(0)
                        }
                    }
                }
                "vaultWipe" -> {
                    vault.wipeAll()
                    result.success("")
                }
                "coskNew" -> {
                    val out = Core.coskNew()
                    val handle = ((out[0].toLong() and 0xff) shl 24) or
                        ((out[1].toLong() and 0xff) shl 16) or
                        ((out[2].toLong() and 0xff) shl 8) or
                        (out[3].toLong() and 0xff)

                    result.success(mapOf("handle" to handle, "pk" to out.copyOfRange(4, out.size)))
                }
                "coskDrop" -> {
                    Core.coskDrop((call.arguments as Number).toLong().toInt())
                    result.success("")
                }
                "provision" -> {
                    val flock = flock(call.argument<String>("flock"))
                    val kek = call.argument<Int>("kek") ?: 0
                    val handle = call.argument<Number>("handle")?.toLong()?.toInt() ?: 0
                    val secret = call.argument<String>("secret") ?: ""
                    val config = call.argument<String>("config") ?: ""
                    val sealed = vault.sealed(flock)

                    withKey(result, "Add a new device", create = false) { vk ->
                        val modules = Core.provision(vk, upgraded(vk, flock, sealed), kek, handle, secret, config)
                        var side = 0
                        while (side * side < modules.size) side++

                        mapOf("side" to side, "modules" to modules)
                    }
                }
                "handoffAvailable" -> result.success(Handoff.available(this))
                "handoff" -> {
                    val flock = flock(call.argument<String>("flock"))
                    val kek = call.argument<Int>("kek") ?: 0
                    val handle = call.argument<Number>("handle")?.toLong()?.toInt() ?: 0
                    val secret = call.argument<String>("secret") ?: ""
                    val config = call.argument<String>("config") ?: ""
                    val sealed = vault.sealed(flock)

                    withKey(result, "Add this phone to Vigil", create = false) { vk ->
                        Handoff.send(this, Core.provisionConfig(vk, upgraded(vk, flock, sealed), kek, handle, secret, config))
                        ""
                    }
                }
                "reminders" -> {
                    @Suppress("UNCHECKED_CAST")
                    Reminders.schedule(this, call.arguments as? List<Map<String, Any>> ?: emptyList())
                    result.success("")
                }
                "remindersAllow" -> {
                    if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                        requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
                    }
                    result.success("")
                }
                "remindedFlock" -> {
                    result.success(reminded)
                    reminded = ""
                }
                "session" -> background(result) { session.load() }
                "sessionSave" -> background(result) {
                    session.save(call.arguments as String)
                    ""
                }
                "sessionClear" -> {
                    session.clear()
                    result.success("")
                }
                "prefs" -> result.success(prefs().getString("prefs", "{}"))
                "prefsSave" -> {
                    prefs().edit().putString("prefs", call.arguments as String).apply()
                    result.success("")
                }
                "version" -> result.success(Core.version())
                else -> result.notImplemented()
            }
        } catch (e: Exception) {
            reply(result, e)
        }
    }

    /**
     * Unlock the vault, do the work with the key off the main thread and
     * wipe the key whatever happens.
     */
    private fun withKey(
        result: MethodChannel.Result,
        reason: String,
        create: Boolean,
        work: (ByteArray) -> Any?
    ) {
        vault.unlock(this, reason, create) { vk, error ->
            if (vk == null) {
                reply(result, error ?: Vault.Cancelled())
                return@unlock
            }

            background(result) {
                try {
                    work(vk)
                } finally {
                    vk.fill(0)
                }
            }
        }
    }

    private fun upgraded(vk: ByteArray, flock: String, sealed: ByteArray): ByteArray {
        if (sealed.size != Core.SEALED_V1_LEN) return sealed

        val upgraded = Core.keksUpgrade(vk, sealed)
        vault.store(flock, upgraded)
        backup(vk, flock, upgraded)

        return upgraded
    }

    /** Back up the KEKs of a flock, a failure leaves it not backed up. */
    private fun backup(vk: ByteArray, flock: String, sealed: ByteArray) {
        val recipient = vault.recipient() ?: return

        vault.dropBackup(flock)

        try {
            vault.storeBackup(flock, Core.backupSeal(vk, recipient, sealed))
        } catch (e: Exception) {
            Log.e(TAG, "failed to back up $flock", e)
            return
        }

        exportQuietly()
    }

    private fun backupAll(vk: ByteArray) {
        val recipient = vault.recipient() ?: throw IllegalStateException("Make a recovery key first.")

        for (flock in vault.flocks()) {
            vault.storeBackup(flock, Core.backupSeal(vk, recipient, upgraded(vk, flock, vault.sealed(flock))))
        }

        exportQuietly()
    }

    /** Write the pending backups to the backup folder, returns how many. */
    private fun export(): Int {
        val tree = vault.folder() ?: return 0
        var count = 0

        for ((flock, backup) in vault.pending()) {
            BackupFolder.write(this, tree, BackupFolder.file(flock), backup)
            vault.exported(flock)
            count++
        }

        return count
    }

    private fun exportQuietly() {
        try {
            export()
        } catch (e: Exception) {
            Log.e(TAG, "failed to export backups", e)
        }
    }

    private fun scan(): List<Map<String, Any>> {
        val tree = vault.folder() ?: throw IllegalStateException("Choose the folder with your backups first.")

        return BackupFolder.list(this, tree).values.mapNotNull { doc ->
            val info = Core.backupInfo(BackupFolder.read(this, doc)) ?: return@mapNotNull null
            val flock = "%016x".format(info[0])

            mapOf("flock" to flock, "made" to info[1], "created" to info[2], "here" to vault.has(flock))
        }.sortedBy { it["flock"] as String }
    }

    /**
     * Restore every flock in the backup folder that this phone has no KEKs
     * for. Without a recipient of its own this phone takes on the one of
     * the given recovery key.
     */
    private fun restore(vk: ByteArray, root: ByteArray): Map<String, Any> {
        val tree = vault.folder() ?: throw IllegalStateException("Choose the folder with your backups first.")
        val restored = mutableListOf<String>()
        val skipped = mutableListOf<String>()
        val failed = mutableListOf<String>()

        for (doc in BackupFolder.list(this, tree).values) {
            val backup = BackupFolder.read(this, doc)
            val info = Core.backupInfo(backup) ?: continue
            val flock = "%016x".format(info[0])

            if (vault.has(flock)) {
                skipped += flock
                continue
            }

            val sealed = try {
                Core.backupRestore(vk, root, backup)
            } catch (e: Core.Failure) {
                if (e.code != RECOVERY_KEY) throw e
                failed += flock
                continue
            }

            vault.store(flock, sealed)
            vault.storeBackup(flock, backup, exported = true)
            restored += flock
        }

        if (restored.isEmpty() && failed.isNotEmpty()) throw Core.Failure(RECOVERY_KEY)

        val recipient = vault.recipient()

        if (recipient == null) {
            if (restored.isNotEmpty()) vault.storeRecipient(Core.backupRecipient(vk, root))
        } else if (!Core.backupVerify(root, recipient)) {
            for (flock in restored) {
                vault.storeBackup(flock, Core.backupSeal(vk, recipient, vault.sealed(flock)))
            }
            exportQuietly()
        }

        return mapOf("restored" to restored, "skipped" to skipped, "failed" to failed)
    }

    private fun bundle(vk: ByteArray, sealed: ByteArray, days: Int): Map<String, Any> {
        val meta = IntArray(2)
        val bundle = Core.ambryBundle(vk, sealed, days, meta)

        return mapOf(
            "bundle" to bundle,
            "generation" to (meta[0].toLong() and 0xffffffffL),
            "expires" to meta[1]
        )
    }

    private fun background(result: MethodChannel.Result, work: () -> Any?) {
        Thread {
            val reply: () -> Unit = try {
                val value = work();
                { result.success(value) }
            } catch (e: Exception) {
                { reply(result, e) }
            }

            runOnUiThread(reply)
        }.start()
    }

    private fun reply(result: MethodChannel.Result, e: Exception) {
        when (e) {
            is Vault.Cancelled -> result.error("cancelled", e.message, null)
            is Vault.Invalidated -> result.error("invalidated", e.message, null)
            is Vault.NoLock -> result.error("nolock", e.message, null)
            is Vault.Missing -> result.error("missing", e.message, null)
            is Core.Failure -> result.error("core", e.message, e.code)
            is IllegalArgumentException -> result.error("invalid", e.message, null)
            else -> result.error("failed", e.message ?: e.toString(), null)
        }
    }

    private fun flock(flock: String?): String {
        require(flock != null && flock.matches(Regex("[0-9a-f]{16}"))) { "That is not a flock ID." }
        return flock
    }

    private fun flockId(flock: String): Long = flock.toULong(16).toLong()

    private fun days(call: MethodCall): Int {
        val days = call.argument<Int>("days") ?: 0
        require(days in 1..3650) { "Encrypted secrets last 1 to 3650 days." }
        return days
    }

    private fun prefs() = getSharedPreferences("reliquary", Context.MODE_PRIVATE)

    private companion object {
        const val CHANNEL = "se.sanctorum.reliquary/core"
        const val TAG = "reliquary"
        const val PICK_FOLDER = 1001
        const val ROOT_LEN = 32
        const val RECOVERY_KEY = 14
    }
}
