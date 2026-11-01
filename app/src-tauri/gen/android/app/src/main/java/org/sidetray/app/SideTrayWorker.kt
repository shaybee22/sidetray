package org.sidetray.app

import android.content.Context
import android.util.Log
import androidx.work.Constraints
import androidx.work.Data
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.ForegroundInfo
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * Background work (A3), all of it in Rust (src/mobile_push.rs):
 *
 * - a sync after a UnifiedPush wake-up, as an expedited job: it starts at once
 *   and may use the network even while the phone dozes;
 * - the periodic sync, about every 15 minutes, when there's no distributor;
 * - passing the distributor's news (a new endpoint, unregistered) to Rust,
 *   which tells the relay.
 *
 * A sync shows its own notifications (src/alerts.rs).
 */
class SideTrayWorker(ctx: Context, params: WorkerParameters) : Worker(ctx, params) {
  override fun doWork(): Result {
    val ctx = applicationContext
    return try {
      SideTrayAndroid.ensureNative(ctx)
      val dir = ctx.dataDir.absolutePath
      val kind = inputData.getString(KIND)
      val out = if (kind != null) {
        SideTrayAndroid.nativePush(dir, kind, inputData.getString(VALUE) ?: "")
      } else {
        SideTrayAndroid.nativeSync(dir)
      }
      Log.i(SideTrayAndroid.TAG, out)
      Result.success()
    } catch (e: Throwable) {
      Log.e(SideTrayAndroid.TAG, "background work failed", e)
      Result.failure()
    }
  }

  // Expedited work runs as a foreground service on Android 11 and older, which needs
  // a notification (from Android 12 it's a job and this isn't called).
  override fun getForegroundInfo(): ForegroundInfo =
    ForegroundInfo(SYNC_NOTIFICATION, SideTrayAndroid.syncNotification(applicationContext))

  companion object {
    private const val KIND = "push_kind"
    private const val VALUE = "push_value"
    private const val SYNC_NOTIFICATION = 7301
    private val online = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

    /** A wake-up arrived: sync now. Another one during a sync queues one more after it. */
    fun syncNow(ctx: Context) {
      val req = OneTimeWorkRequestBuilder<SideTrayWorker>()
        .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
        .setConstraints(online)
        .build()
      WorkManager.getInstance(ctx).enqueueUniqueWork("sync-now", ExistingWorkPolicy.APPEND_OR_REPLACE, req)
    }

    /** The distributor's news, for Rust to pass on to the relay. */
    fun pushEvent(ctx: Context, kind: String, value: String) {
      val req = OneTimeWorkRequestBuilder<SideTrayWorker>()
        .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
        .setInputData(Data.Builder().putString(KIND, kind).putString(VALUE, value).build())
        .build()
      WorkManager.getInstance(ctx).enqueueUniqueWork("push-event", ExistingWorkPolicy.APPEND_OR_REPLACE, req)
    }

    /** The periodic sync on or off (on whenever wake-ups don't reach this phone). */
    fun periodic(ctx: Context, on: Boolean) {
      val wm = WorkManager.getInstance(ctx)
      if (on) {
        val req = PeriodicWorkRequestBuilder<SideTrayWorker>(15, TimeUnit.MINUTES).setConstraints(online).build()
        wm.enqueueUniquePeriodicWork("sync-periodic", ExistingPeriodicWorkPolicy.KEEP, req)
      } else {
        wm.cancelUniqueWork("sync-periodic")
      }
    }
  }
}
