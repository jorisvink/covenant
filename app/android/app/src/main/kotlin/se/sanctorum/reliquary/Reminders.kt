package se.sanctorum.reliquary

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequest
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

object Reminders {
    const val EXTRA_FLOCK = "se.sanctorum.reliquary.extra.FLOCK"

    private const val TAG = "expiry"
    private const val CHANNEL = "expiry"

    fun schedule(context: Context, reminders: List<Map<String, Any>>) {
        val work = WorkManager.getInstance(context)
        val now = System.currentTimeMillis()

        work.cancelAllWorkByTag(TAG)

        for (reminder in reminders) {
            val flock = reminder["flock"] as? String ?: continue
            val days = (reminder["days"] as? Number)?.toInt() ?: continue
            val at = (reminder["at"] as? Number)?.toLong() ?: continue

            if (at <= now) continue

            val request = OneTimeWorkRequest.Builder(Reminder::class.java)
                .setInitialDelay(at - now, TimeUnit.MILLISECONDS)
                .setInputData(Data.Builder().putString("flock", flock).putInt("days", days).build())
                .addTag(TAG)
                .build()

            work.enqueueUniqueWork("$TAG-$flock-$days", ExistingWorkPolicy.REPLACE, request)
        }
    }

    fun show(context: Context, flock: String, days: Int) {
        if (context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            return
        }

        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, "Key update reminders", NotificationManager.IMPORTANCE_DEFAULT)
        )

        val open = Intent(context, MainActivity::class.java)
            .putExtra(EXTRA_FLOCK, flock)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val tap = PendingIntent.getActivity(
            context, flock.hashCode(), open,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val left = if (days == 1) "1 day" else "$days days"
        val notification = Notification.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_notify)
            .setContentTitle("Encrypted key update expires soon")
            .setContentText("Flock $flock expires in $left, send a new one to keep its devices connected.")
            .setStyle(
                Notification.BigTextStyle()
                    .bigText("Flock $flock expires in $left, send a new one to keep its devices connected.")
            )
            .setContentIntent(tap)
            .setAutoCancel(true)
            .build()

        manager.notify(flock.hashCode(), notification)
    }
}

class Reminder(context: Context, params: WorkerParameters) : Worker(context, params) {
    override fun doWork(): Result {
        val flock = inputData.getString("flock") ?: return Result.success()
        Reminders.show(applicationContext, flock, inputData.getInt("days", 0))
        return Result.success()
    }
}
