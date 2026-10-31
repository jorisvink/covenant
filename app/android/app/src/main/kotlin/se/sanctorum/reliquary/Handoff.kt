package se.sanctorum.reliquary

import android.app.Activity
import android.content.Context
import android.net.Uri
import android.os.Bundle

object Handoff {
    const val PACKAGE = "se.sanctorum.vigil"
    const val AUTHORITY = "se.sanctorum.vigil.import"
    const val METHOD = "import"
    const val EXTRA = "config"

    fun available(context: Context): Boolean =
        context.packageManager.resolveContentProvider(AUTHORITY, 0) != null

    fun send(activity: Activity, config: ByteArray) {
        val extras = Bundle().apply { putByteArray(EXTRA, config) }

        try {
            val reply = try {
                activity.contentResolver.call(Uri.parse("content://$AUTHORITY"), METHOD, null, extras)
            } catch (e: SecurityException) {
                throw IllegalStateException("This Vigil does not take devices from Reliquary, use a QR code instead.")
            } catch (e: IllegalArgumentException) {
                throw IllegalStateException("Vigil is not installed on this phone.")
            }

            check(reply?.getBoolean("ok") == true) { "Vigil did not take the device, use a QR code instead." }
        } finally {
            config.fill(0)
            extras.clear()
        }

        val launch = activity.packageManager.getLaunchIntentForPackage(PACKAGE)
        checkNotNull(launch) { "Vigil took the device but cannot be opened, open it yourself." }
        activity.startActivity(launch)
    }
}
