package io.nekohasekai.sagernet.bg

import android.content.Context
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy.UPDATE
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequest
import androidx.work.PeriodicWorkRequest
import androidx.work.WorkerParameters
import androidx.work.multiprocess.RemoteWorkManager
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.GroupManager
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.group.GroupUpdater
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.app
import java.util.concurrent.TimeUnit

object SubscriptionUpdater {

    private const val WORK_NAME = "SubscriptionUpdater"
    private const val SMART_HEAD_WORK_NAME = "SubscriptionSmartHeadUpdater"
    private const val SMART_HEAD_INTERVAL_MIN = 60L
    private const val FORCE_UPDATE_INTERVAL_SEC = 6 * 60 * 60L

    suspend fun reconfigureUpdater() {
        RemoteWorkManager.getInstance(app).cancelUniqueWork(WORK_NAME)
        RemoteWorkManager.getInstance(app).cancelUniqueWork(SMART_HEAD_WORK_NAME)

        val subscriptions = SagerDatabase.groupDao.subscriptions()
            .filter { it.subscription!!.autoUpdate }

        if (subscriptions.isNotEmpty()) {
            // PeriodicWorkRequest.MIN_PERIODIC_INTERVAL_MILLIS
            var minDelay =
                subscriptions.minByOrNull { it.subscription!!.autoUpdateDelay }!!
                    .subscription!!
                    .autoUpdateDelay
                    .toLong()
            val now = System.currentTimeMillis() / 1000L
            var minInitDelay =
                subscriptions.minOf { now - it.subscription!!.lastUpdated - (minDelay * 60) }
            if (minDelay < 15) minDelay = 15
            if (minInitDelay > 60) minInitDelay = 60

            // main process
            RemoteWorkManager.getInstance(app).enqueueUniquePeriodicWork(
                WORK_NAME,
                UPDATE,
                PeriodicWorkRequest.Builder(UpdateTask::class.java, minDelay, TimeUnit.MINUTES)
                    .apply {
                        if (minInitDelay > 0) setInitialDelay(minInitDelay, TimeUnit.SECONDS)
                    }
                    .build()
            )
        }

        scheduleSmartHeadUpdater()
    }

    class UpdateTask(
        appContext: Context, params: WorkerParameters
    ) : CoroutineWorker(appContext, params) {

        val nm = NotificationManagerCompat.from(applicationContext)

        val notification = NotificationCompat.Builder(applicationContext, "service-subscription")
            .setWhen(0)
            .setTicker(applicationContext.getString(R.string.forward_success))
            .setContentTitle(applicationContext.getString(R.string.subscription_update))
            .setSmallIcon(R.drawable.ic_service_active)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)

        override suspend fun doWork(): Result {
            var subscriptions =
                SagerDatabase.groupDao.subscriptions().filter { it.subscription!!.autoUpdate }
            if (!DataStore.serviceState.connected) {
                Logs.d("work: not connected")
                subscriptions = subscriptions.filter { !it.subscription!!.updateWhenConnectedOnly }
            }

            if (subscriptions.isNotEmpty()) for (profile in subscriptions) {
                val subscription = profile.subscription!!
                val elapsedSec = (System.currentTimeMillis() / 1000).toInt() - subscription.lastUpdated

                val minDelaySec = subscription.autoUpdateDelay * 60
                if (elapsedSec < minDelaySec && elapsedSec < FORCE_UPDATE_INTERVAL_SEC) {
                    Logs.d("work: not updating " + profile.displayName())
                    continue
                }
                Logs.d("work: updating " + profile.displayName())
                if (elapsedSec >= FORCE_UPDATE_INTERVAL_SEC) {
                    GroupUpdater.markForceUpdate(profile.id)
                }

                notification.setContentText(
                    applicationContext.getString(
                        R.string.subscription_update_message, profile.displayName()
                    )
                )
                nm.notify(2, notification.build())

                GroupUpdater.executeUpdate(profile, false)
            }

            nm.cancel(2)

            return Result.success()
        }
    }

    private suspend fun scheduleSmartHeadUpdater() {
        val candidates = SagerDatabase.groupDao.subscriptions().filter { group ->
            GroupManager.isDefaultSubscriptionGroup(group) ||
                GroupManager.isDedicatedSubscriptionGroup(group)
        }
        if (candidates.isEmpty()) return

        RemoteWorkManager.getInstance(app).enqueueUniqueWork(
            SMART_HEAD_WORK_NAME,
            ExistingWorkPolicy.REPLACE,
            OneTimeWorkRequest.Builder(SmartHeadUpdateTask::class.java)
                .setInitialDelay(SMART_HEAD_INTERVAL_MIN, TimeUnit.MINUTES)
                .build()
        )
    }

    class SmartHeadUpdateTask(
        appContext: Context, params: WorkerParameters
    ) : CoroutineWorker(appContext, params) {

        override suspend fun doWork(): Result {
            val subscriptions = SagerDatabase.groupDao.subscriptions().filter { group ->
                GroupManager.isDefaultSubscriptionGroup(group) ||
                    GroupManager.isDedicatedSubscriptionGroup(group)
            }

            if (subscriptions.isNotEmpty()) for (profile in subscriptions) {
                val subscription = profile.subscription!!
                val elapsedSec =
                    (System.currentTimeMillis() / 1000).toInt() - subscription.lastUpdated
                if (elapsedSec >= FORCE_UPDATE_INTERVAL_SEC) {
                    GroupUpdater.markForceUpdate(profile.id)
                }
                Logs.d("smart-head: checking " + profile.displayName())
                GroupUpdater.executeUpdate(profile, false)
            }

            scheduleSmartHeadUpdater()
            return Result.success()
        }
    }
}
