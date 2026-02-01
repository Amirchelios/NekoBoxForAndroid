package io.nekohasekai.sagernet.group

import io.nekohasekai.sagernet.*
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.GroupManager
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.database.ProfileManager
import io.nekohasekai.sagernet.bg.proto.TestInstance
import moe.matsuri.nb4a.proxy.config.ConfigBean
import io.nekohasekai.sagernet.database.ProxyGroup
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.database.SubscriptionBean
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.http.HttpBean
import io.nekohasekai.sagernet.fmt.hysteria.HysteriaBean
import io.nekohasekai.sagernet.fmt.naive.NaiveBean
import io.nekohasekai.sagernet.fmt.trojan.TrojanBean
import io.nekohasekai.sagernet.fmt.trojan_go.TrojanGoBean
import io.nekohasekai.sagernet.fmt.v2ray.StandardV2RayBean
import io.nekohasekai.sagernet.fmt.v2ray.isTLS
import io.nekohasekai.sagernet.ktx.*
import io.nekohasekai.sagernet.utils.DnsAutoSelector
import kotlinx.coroutines.delay
import kotlinx.coroutines.*
import java.net.Inet4Address
import java.net.InetAddress
import java.util.*
import java.util.concurrent.atomic.AtomicInteger

@Suppress("EXPERIMENTAL_API_USAGE")
abstract class GroupUpdater {

    abstract suspend fun doUpdate(
        proxyGroup: ProxyGroup,
        subscription: SubscriptionBean,
        userInterface: GroupManager.Interface?,
        byUser: Boolean
    )

    data class Progress(
        var max: Int
    ) {
        var progress by AtomicInteger()
    }

    protected suspend fun forceResolve(
        profiles: List<AbstractBean>, groupId: Long?
    ) {
        val ipv6Mode = DataStore.ipv6Mode
        val lookupPool = newFixedThreadPoolContext(5, "DNS Lookup")
        val lookupJobs = mutableListOf<Job>()
        val progress = Progress(profiles.size)
        if (groupId != null) {
            GroupUpdater.progress[groupId] = progress
            GroupManager.postReload(groupId)
        }
        val ipv6First = ipv6Mode >= IPv6Mode.PREFER

        for (profile in profiles) {
            when (profile) {
                // SNI rewrite unsupported
                is NaiveBean -> continue
            }

            if (profile.serverAddress.isIpAddress()) continue

            lookupJobs.add(GlobalScope.launch(lookupPool) {
                try {
                    val results = if (
                        SagerNet.underlyingNetwork != null &&
                        DataStore.enableFakeDns &&
                        DataStore.serviceState.started &&
                        DataStore.serviceMode == Key.MODE_VPN
                    ) {
                        // FakeDNS
                        SagerNet.underlyingNetwork!!
                            .getAllByName(profile.serverAddress)
                            .filterNotNull()
                    } else {
                        // System DNS is enough (when VPN connected, it uses v2ray-core)
                        InetAddress.getAllByName(profile.serverAddress).filterNotNull()
                    }
                    if (results.isEmpty()) error("empty response")
                    rewriteAddress(profile, results, ipv6First)
                } catch (e: Exception) {
                    Logs.d("Lookup ${profile.serverAddress} failed: ${e.readableMessage}", e)
                }
                if (groupId != null) {
                    progress.progress++
                    GroupManager.postReload(groupId)
                }
            })
        }

        lookupJobs.joinAll()
        lookupPool.close()
    }

    protected fun rewriteAddress(
        bean: AbstractBean, addresses: List<InetAddress>, ipv6First: Boolean
    ) {
        val address = addresses.sortedBy { (it is Inet4Address) xor ipv6First }[0].hostAddress

        with(bean) {
            when (this) {
                is HttpBean -> {
                    if (isTLS() && sni.isBlank()) sni = bean.serverAddress
                }
                is StandardV2RayBean -> {
                    when (security) {
                        "tls" -> if (sni.isBlank()) sni = bean.serverAddress
                    }
                }
                is TrojanBean -> {
                    if (sni.isBlank()) sni = bean.serverAddress
                }
                is TrojanGoBean -> {
                    if (sni.isBlank()) sni = bean.serverAddress
                }
                is HysteriaBean -> {
                    if (sni.isBlank()) sni = bean.serverAddress
                }
            }

            bean.serverAddress = address
        }
    }

    companion object {

        val updating = Collections.synchronizedSet<Long>(mutableSetOf())
        val progress = Collections.synchronizedMap<Long, Progress>(mutableMapOf())
        private const val DEFAULT_DEDICATED_LINK_URL =
            "https://drive.usercontent.google.com/u/0/uc?id=1JHaY3RHNHR2sYd_zu9CvNH6IdFv2ggec&export=download"

        fun startUpdate(proxyGroup: ProxyGroup, byUser: Boolean) {
            runOnDefaultDispatcher {
                executeUpdate(proxyGroup, byUser)
            }
        }

        suspend fun executeUpdate(proxyGroup: ProxyGroup, byUser: Boolean): Boolean {
            return coroutineScope {
                if (!updating.add(proxyGroup.id)) cancel()
                GroupManager.postReload(proxyGroup.id)

                val subscription = proxyGroup.subscription!!
                val connected = DataStore.serviceState.connected
                val userInterface = GroupManager.userInterface

                if (byUser && (subscription.link?.startsWith("http://") == true || subscription.updateWhenConnectedOnly) && !connected) {
                    if (userInterface == null || !userInterface.confirm(app.getString(R.string.update_subscription_warning))) {
                        finishUpdate(proxyGroup)
                        cancel()
                        return@coroutineScope true
                    }
                }

                try {
                    if (!connected) {
                        val dedicated = findDedicatedCandidate()
                        if (dedicated != null) {
                            val reachable = ensureDedicatedReachable(dedicated)
                            if (!reachable) {
                                userInterface?.onUpdateFailure(proxyGroup, app.getString(R.string.dedicated_unreachable))
                            }
                            val state = captureInternalProxyState()
                            val connectedInternal = if (reachable) tryConnectWith(dedicated) else false
                            if (connectedInternal) {
                                return@coroutineScope runCatching {
                                    RawUpdater.doUpdate(proxyGroup, subscription, userInterface, byUser)
                                    true
                                }.getOrElse { e ->
                                    Logs.w(e)
                                    userInterface?.onUpdateFailure(proxyGroup, e.readableMessage)
                                    finishUpdate(proxyGroup)
                                    false
                                }
                            } else {
                                restoreInternalProxyState(state)
                            }
                        }

                        // Dedicated config empty or not reachable -> direct network path.
                        if (runCatching {
                                RawUpdater.doUpdate(proxyGroup, subscription, userInterface, byUser)
                            }.isSuccess
                        ) {
                            return@coroutineScope true
                        }

                        // Try auto DNS selection to improve reachability (e.g., GitHub).
                        applyAutoDnsForUpdate()

                        // Retry again on direct network after DNS switch.
                        if (runCatching {
                                RawUpdater.doUpdate(proxyGroup, subscription, userInterface, byUser)
                            }.isSuccess
                        ) {
                            return@coroutineScope true
                        }

                        // Still failing: open internal browser for dedicated link download.
                        promptOpenDedicatedLink(userInterface)
                        finishUpdate(proxyGroup)
                        return@coroutineScope false
                    }

                    RawUpdater.doUpdate(proxyGroup, subscription, userInterface, byUser)
                    true
                } catch (e: Throwable) {
                    Logs.w(e)
                    userInterface?.onUpdateFailure(proxyGroup, e.readableMessage)
                    promptOpenDedicatedLink(userInterface)
                    finishUpdate(proxyGroup)
                    false
                }
            }
        }

        private fun findDedicatedCandidate(): ProxyEntity? {
            val all = SagerDatabase.proxyDao.getAll()
            val dedicated = all.firstOrNull { GroupManager.isDedicatedConfig(it) } ?: return null
            val bean = dedicated.requireBean()
            val hasConfig = dedicated.type == ProxyEntity.TYPE_CONFIG &&
                bean is ConfigBean &&
                bean.type == 0 &&
                bean.config.isNotBlank()
            return if (hasConfig) dedicated else null
        }

        private suspend fun ensureDedicatedReachable(profile: ProxyEntity): Boolean {
            if (profile.status == 1 && profile.ping > 0) return true
            return try {
                val tester = TestInstance(profile, "https://www.gstatic.com/generate_204", 5000)
                val latency = tester.doTest()
                if (latency > 0) {
                    profile.status = 1
                    profile.ping = latency
                    ProfileManager.updateProfile(profile)
                    true
                } else {
                    false
                }
            } catch (e: Exception) {
                Logs.w(e)
                false
            }
        }

        private data class InternalProxyState(
            val serviceMode: String,
            val selectedProxy: Long,
            val currentProfile: Long,
            val internalActive: Boolean,
            val internalProfileId: Long,
            val internalUserSelected: Long,
            val wasStarted: Boolean,
        )

        private fun captureInternalProxyState(): InternalProxyState {
            return InternalProxyState(
                serviceMode = DataStore.serviceMode,
                selectedProxy = DataStore.selectedProxy,
                currentProfile = DataStore.currentProfile,
                internalActive = DataStore.internalProxyActive,
                internalProfileId = DataStore.internalProxyProfileId,
                internalUserSelected = DataStore.internalProxyUserSelected,
                wasStarted = DataStore.serviceState.started,
            )
        }

        private fun restoreInternalProxyState(state: InternalProxyState) {
            DataStore.internalProxyActive = state.internalActive
            DataStore.internalProxyProfileId = state.internalProfileId
            DataStore.internalProxyUserSelected = state.internalUserSelected
            DataStore.selectedProxy = state.selectedProxy
            DataStore.currentProfile = state.currentProfile
            DataStore.serviceMode = state.serviceMode
            if (!state.wasStarted) {
                SagerNet.stopService()
            }
        }

        private suspend fun tryConnectWith(profile: ProxyEntity): Boolean {
            if (DataStore.clientMode) return false
            val prevSelected = DataStore.selectedProxy
            if (!DataStore.internalProxyActive) {
                DataStore.internalProxyUserSelected = prevSelected
            }
            DataStore.selectedProxy = profile.id
            DataStore.currentProfile = profile.id
            DataStore.serviceMode = Key.MODE_PROXY
            DataStore.internalProxyProfileId = profile.id
            DataStore.internalProxyActive = true

            if (!DataStore.serviceState.started) {
                SagerNet.startService()
            } else {
                SagerNet.reloadService()
            }

            val timeoutMs = 60_000L
            val start = System.currentTimeMillis()
            while (System.currentTimeMillis() - start < timeoutMs) {
                if (DataStore.serviceState.connected) return true
                delay(500L)
            }
            return false
        }

        private suspend fun applyAutoDnsForUpdate() {
            val provider = DnsAutoSelector.selectBest() ?: return
            val servers = listOfNotNull(provider.primary, provider.secondary)
            val groups = SagerDatabase.groupDao.allGroups()
            for (group in groups) {
                val link = group.subscription?.link?.trim().orEmpty()
                if (group.type == GroupType.SUBSCRIPTION &&
                    (link.equals(DEFAULT_SUBSCRIPTION_LINK, true) ||
                        link.equals(GroupManager.DEDICATED_SUBSCRIPTION_LINK, true))
                ) {
                    DataStore.setAutoDnsServers(group.id, servers)
                }
            }
        }

        private suspend fun promptOpenDedicatedLink(userInterface: GroupManager.Interface?) {
            val adapter = userInterface as? GroupInterfaceAdapter ?: return
            val group = GroupManager.ensureDedicatedSubscriptionGroup() ?: return
            runOnMainDispatcher {
                val intent = android.content.Intent(adapter.context, io.nekohasekai.sagernet.ui.InternalBrowserActivity::class.java)
                intent.putExtra(io.nekohasekai.sagernet.ui.InternalBrowserActivity.EXTRA_TARGET_GROUP_ID, group.id)
                intent.putExtra(io.nekohasekai.sagernet.ui.InternalBrowserActivity.EXTRA_INITIAL_URL, DEFAULT_DEDICATED_LINK_URL)
                intent.putExtra(io.nekohasekai.sagernet.ui.InternalBrowserActivity.EXTRA_DISABLE_PROXY, true)
                adapter.context.startActivity(intent)
            }
        }

        suspend fun finishUpdate(proxyGroup: ProxyGroup) {
            updating.remove(proxyGroup.id)
            progress.remove(proxyGroup.id)
            GroupManager.postUpdate(proxyGroup)
        }

    }

}
