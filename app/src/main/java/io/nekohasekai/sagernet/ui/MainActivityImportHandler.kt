package io.nekohasekai.sagernet.ui

import android.net.Uri
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import io.nekohasekai.sagernet.GroupType
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.ProfileManager
import io.nekohasekai.sagernet.database.ProxyGroup
import io.nekohasekai.sagernet.database.SubscriptionBean
import io.nekohasekai.sagernet.database.GroupManager
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.KryoConverters
import io.nekohasekai.sagernet.ktx.alert
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import io.nekohasekai.sagernet.ktx.parseProxies
import io.nekohasekai.sagernet.ktx.readableMessage
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import moe.matsuri.nb4a.utils.Util

class MainActivityImportHandler(
    private val activity: MainActivity
) {
    suspend fun handleIntent(uri: Uri) {
        if (uri.scheme == "sn" && uri.host == "subscription" || uri.scheme == "clash") {
            importSubscription(uri)
        } else {
            importProfile(uri)
        }
    }

    suspend fun importSubscription(uri: Uri) {
        val group: ProxyGroup

        val url = uri.getQueryParameter("url")
        if (!url.isNullOrBlank()) {
            group = ProxyGroup(type = GroupType.SUBSCRIPTION)
            val subscription = SubscriptionBean()
            group.subscription = subscription
            subscription.link = url
            group.name = uri.getQueryParameter("name")
        } else {
            val data = uri.encodedQuery.takeIf { !it.isNullOrBlank() } ?: return
            try {
                group = KryoConverters.deserialize(
                    ProxyGroup().apply { export = true },
                    Util.zlibDecompress(Util.b64Decode(data))
                ).apply {
                    export = false
                }
            } catch (e: Exception) {
                onMainDispatcher { activity.alert(e.readableMessage).show() }
                return
            }
        }

        val name = group.name.takeIf { !it.isNullOrBlank() } ?: group.subscription?.link ?: group.subscription?.token
        if (name.isNullOrBlank()) return

        group.name = group.name.takeIf { !it.isNullOrBlank() } ?: ("Subscription #" + System.currentTimeMillis())

        onMainDispatcher {
            activity.displayFragmentWithId(R.id.nav_configuration)
            MaterialAlertDialogBuilder(activity)
                .setTitle(R.string.subscription_import)
                .setMessage(activity.getString(R.string.subscription_import_message, name))
                .setPositiveButton(R.string.yes) { _, _ ->
                    runOnDefaultDispatcher {
                        finishImportSubscription(group)
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }

    private suspend fun finishImportSubscription(subscription: ProxyGroup) {
        GroupManager.createGroup(subscription)
        io.nekohasekai.sagernet.group.GroupUpdater.startUpdate(subscription, true)
    }

    suspend fun importProfile(uri: Uri) {
        val profile = try {
            parseProxies(uri.toString()).getOrNull(0) ?: error(activity.getString(R.string.no_proxies_found))
        } catch (e: Exception) {
            onMainDispatcher { activity.alert(e.readableMessage).show() }
            return
        }

        onMainDispatcher {
            MaterialAlertDialogBuilder(activity)
                .setTitle(R.string.profile_import)
                .setMessage(activity.getString(R.string.profile_import_message, profile.displayName()))
                .setPositiveButton(R.string.yes) { _, _ ->
                    runOnDefaultDispatcher {
                        finishImportProfile(profile)
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }

    private suspend fun finishImportProfile(profile: AbstractBean) {
        val targetId = DataStore.selectedGroupForImport()
        ProfileManager.createProfile(targetId, profile)
        onMainDispatcher {
            activity.displayFragmentWithId(R.id.nav_configuration)
            activity.snackbar(activity.resources.getQuantityString(R.plurals.added, 1, 1)).show()
        }
    }
}
