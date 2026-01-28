package io.nekohasekai.sagernet.database

import io.nekohasekai.sagernet.DEFAULT_SUBSCRIPTION_GROUP_NAME
import io.nekohasekai.sagernet.DEFAULT_SUBSCRIPTION_LINK
import io.nekohasekai.sagernet.GroupType
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.bg.SubscriptionUpdater
import io.nekohasekai.sagernet.ktx.applyDefaultValues
import io.nekohasekai.sagernet.ktx.Logs
import moe.matsuri.nb4a.proxy.config.ConfigBean

object GroupManager {

    const val YOUTUBE_INSTAGRAM_CONFIG_NAME = "باز کننده یوتویب و اینستاگرام"
    const val DEDICATED_SUBSCRIPTION_GROUP_NAME = "کانفیگ اختصاصی"
    const val DEDICATED_SUBSCRIPTION_LINK =
        "https://raw.githubusercontent.com/Amirchelios/NG_manager/refs/heads/main/ml.txt"
    const val DEDICATED_CONFIG_NAME = "کانفیگ اختصاصی"

    interface Listener {
        suspend fun groupAdd(group: ProxyGroup)
        suspend fun groupUpdated(group: ProxyGroup)

        suspend fun groupRemoved(groupId: Long)
        suspend fun groupUpdated(groupId: Long)
    }

    interface Interface {
        suspend fun confirm(message: String): Boolean
        suspend fun alert(message: String)
        suspend fun onUpdateSuccess(
            group: ProxyGroup,
            changed: Int,
            added: List<String>,
            updated: Map<String, String>,
            deleted: List<String>,
            duplicate: List<String>,
            byUser: Boolean
        )

        suspend fun onUpdateFailure(group: ProxyGroup, message: String)
    }

    private val listeners = ArrayList<Listener>()
    var userInterface: Interface? = null

    suspend fun iterator(what: suspend Listener.() -> Unit) {
        synchronized(listeners) {
            listeners.toList()
        }.forEach { listener ->
            what(listener)
        }
    }

    fun addListener(listener: Listener) {
        synchronized(listeners) {
            listeners.add(listener)
        }
    }

    fun removeListener(listener: Listener) {
        synchronized(listeners) {
            listeners.remove(listener)
        }
    }

    suspend fun clearGroup(groupId: Long) {
        DataStore.selectedProxy = 0L
        SagerDatabase.proxyDao.deleteAll(groupId)
        iterator { groupUpdated(groupId) }
    }

    fun rearrange(groupId: Long) {
        val entities = SagerDatabase.proxyDao.getByGroup(groupId)
        for (index in entities.indices) {
            entities[index].userOrder = (index + 1).toLong()
        }
        SagerDatabase.proxyDao.updateProxy(entities)
    }

    suspend fun postUpdate(group: ProxyGroup) {
        iterator { groupUpdated(group) }
    }

    suspend fun postUpdate(groupId: Long) {
        postUpdate(SagerDatabase.groupDao.getById(groupId) ?: return)
    }

    suspend fun postReload(groupId: Long) {
        iterator { groupUpdated(groupId) }
    }

    suspend fun createGroup(group: ProxyGroup): ProxyGroup {
        group.userOrder = SagerDatabase.groupDao.nextOrder() ?: 1
        group.id = SagerDatabase.groupDao.createGroup(group.applyDefaultValues())
        iterator { groupAdd(group) }
        if (group.type == GroupType.SUBSCRIPTION) {
            SubscriptionUpdater.reconfigureUpdater()
        }
        return group
    }

    suspend fun updateGroup(group: ProxyGroup) {
        SagerDatabase.groupDao.updateGroup(group)
        iterator { groupUpdated(group) }
        if (group.type == GroupType.SUBSCRIPTION) {
            SubscriptionUpdater.reconfigureUpdater()
        }
    }

    suspend fun deleteGroup(groupId: Long) {
        val group = SagerDatabase.groupDao.getById(groupId) ?: return
        if (isProtectedGroup(group)) return
        SagerDatabase.groupDao.deleteById(groupId)
        SagerDatabase.proxyDao.deleteByGroup(groupId)
        iterator { groupRemoved(groupId) }
        SubscriptionUpdater.reconfigureUpdater()
    }

    suspend fun deleteGroup(group: List<ProxyGroup>) {
        val deletable = group.filterNot { isProtectedGroup(it) }
        if (deletable.isEmpty()) return
        SagerDatabase.groupDao.deleteGroup(deletable)
        SagerDatabase.proxyDao.deleteByGroup(deletable.map { it.id }.toLongArray())
        for (proxyGroup in deletable) iterator { groupRemoved(proxyGroup.id) }
        SubscriptionUpdater.reconfigureUpdater()
    }

    suspend fun ensureDefaultSubscriptionGroup(): ProxyGroup? {
        val existing = SagerDatabase.groupDao.allGroups().firstOrNull { isProtectedGroup(it) }
        if (existing != null) {
            if (existing.name != DEFAULT_SUBSCRIPTION_GROUP_NAME) {
                existing.name = DEFAULT_SUBSCRIPTION_GROUP_NAME
                SagerDatabase.groupDao.updateGroup(existing)
                iterator { groupUpdated(existing) }
            }
            ensureDefaultAutoSelectConfig(existing)
            ensureDefaultYoutubeInstagramConfig(existing)
            return existing
        }
        val group = ProxyGroup(type = GroupType.SUBSCRIPTION).apply {
            name = DEFAULT_SUBSCRIPTION_GROUP_NAME
            subscription = SubscriptionBean().applyDefaultValues().also {
                it.link = DEFAULT_SUBSCRIPTION_LINK
            }
        }
        return createGroup(group).also {
            if (it != null) {
                ensureDefaultAutoSelectConfig(it)
                ensureDefaultYoutubeInstagramConfig(it)
            }
        }
    }

    fun isProtectedGroup(group: ProxyGroup): Boolean {
        val link = group.subscription?.link?.trim().orEmpty()
        return group.type == GroupType.SUBSCRIPTION &&
            (link.equals(DEFAULT_SUBSCRIPTION_LINK, ignoreCase = true) ||
                link.equals(DEDICATED_SUBSCRIPTION_LINK, ignoreCase = true))
    }

    suspend fun ensureDedicatedSubscriptionGroup(): ProxyGroup? {
        val existing = SagerDatabase.groupDao.allGroups().firstOrNull { group ->
            group.type == GroupType.SUBSCRIPTION &&
                group.subscription?.link?.trim()?.equals(DEDICATED_SUBSCRIPTION_LINK, true) == true
        }
        if (existing != null) {
            if (existing.name != DEDICATED_SUBSCRIPTION_GROUP_NAME) {
                existing.name = DEDICATED_SUBSCRIPTION_GROUP_NAME
                SagerDatabase.groupDao.updateGroup(existing)
                iterator { groupUpdated(existing) }
            }
            ensureDedicatedAutoSelectConfig(existing)
            return existing
        }
        val group = ProxyGroup(type = GroupType.SUBSCRIPTION).apply {
            name = DEDICATED_SUBSCRIPTION_GROUP_NAME
            subscription = SubscriptionBean().applyDefaultValues().also {
                it.link = DEDICATED_SUBSCRIPTION_LINK
            }
        }
        return createGroup(group).also {
            if (it != null) {
                ensureDedicatedAutoSelectConfig(it)
            }
        }
    }

    fun isYoutubeInstagramConfig(proxy: ProxyEntity): Boolean {
        if (proxy.type != ProxyEntity.TYPE_CONFIG) return false
        val bean = proxy.requireBean() as? ConfigBean ?: return false
        return bean.type == 0 && bean.name == YOUTUBE_INSTAGRAM_CONFIG_NAME
    }

    fun isAutoSelectConfig(proxy: ProxyEntity): Boolean {
        if (proxy.type != ProxyEntity.TYPE_CONFIG) return false
        val bean = proxy.requireBean() as? ConfigBean ?: return false
        return bean.type == 0
    }

    fun isAutoSelectAggregate(proxy: ProxyEntity): Boolean {
        if (proxy.type != ProxyEntity.TYPE_CONFIG) return false
        val bean = proxy.requireBean() as? ConfigBean ?: return false
        return bean.type == 0 && bean.config.isBlank()
    }

    fun isProtectedProfile(group: ProxyGroup, proxy: ProxyEntity): Boolean {
        return isProtectedGroup(group) && isYoutubeInstagramConfig(proxy)
    }

    fun isProtectedProfile(proxy: ProxyEntity): Boolean {
        val group = SagerDatabase.groupDao.getById(proxy.groupId) ?: return false
        return isProtectedProfile(group, proxy)
    }

    fun isDefaultAutoSelectConfig(proxy: ProxyEntity): Boolean {
        val group = SagerDatabase.groupDao.getById(proxy.groupId) ?: return false
        val link = group.subscription?.link?.trim().orEmpty()
        if (!link.equals(DEFAULT_SUBSCRIPTION_LINK, ignoreCase = true)) return false
        val bean = proxy.requireBean() as? ConfigBean ?: return false
        return proxy.type == ProxyEntity.TYPE_CONFIG &&
            bean.type == 0 &&
            bean.name == SagerNet.application.getString(R.string.menu_auto_select)
    }

    fun isDedicatedConfig(proxy: ProxyEntity): Boolean {
        val group = SagerDatabase.groupDao.getById(proxy.groupId) ?: return false
        val link = group.subscription?.link?.trim().orEmpty()
        if (!link.equals(DEDICATED_SUBSCRIPTION_LINK, ignoreCase = true)) return false
        val bean = proxy.requireBean() as? ConfigBean ?: return false
        return proxy.type == ProxyEntity.TYPE_CONFIG &&
            bean.type == 0 &&
            bean.name == DEDICATED_CONFIG_NAME
    }

    fun isRemovalBlocked(group: ProxyGroup, proxy: ProxyEntity): Boolean {
        return isProtectedProfile(group, proxy) || isAutoSelectConfig(proxy)
    }

    fun isRemovalBlocked(proxy: ProxyEntity): Boolean {
        val group = SagerDatabase.groupDao.getById(proxy.groupId) ?: return false
        return isRemovalBlocked(group, proxy)
    }

}

private suspend fun ensureDefaultYoutubeInstagramConfig(group: ProxyGroup) {
    val existing = SagerDatabase.proxyDao.getByGroup(group.id).firstOrNull { proxy ->
        if (proxy.type != ProxyEntity.TYPE_CONFIG) return@firstOrNull false
        val bean = proxy.requireBean() as? ConfigBean ?: return@firstOrNull false
        bean.type == 0 && bean.name == GroupManager.YOUTUBE_INSTAGRAM_CONFIG_NAME
    }
    if (existing != null) return

    val configText = runCatching {
        SagerNet.application.assets.open("sing-box-config-all.json").bufferedReader().use {
            it.readText()
        }
    }.getOrElse {
        Logs.w(it)
        return
    }

    val bean = ConfigBean().applyDefaultValues().apply {
        type = 0
        config = configText
        name = GroupManager.YOUTUBE_INSTAGRAM_CONFIG_NAME
    }
    ProfileManager.createProfile(group.id, bean)
}

private suspend fun ensureDefaultAutoSelectConfig(group: ProxyGroup) {
    val autoName = SagerNet.application.getString(R.string.menu_auto_select)
    val existing = SagerDatabase.proxyDao.getByGroup(group.id).firstOrNull { proxy ->
        if (proxy.type != ProxyEntity.TYPE_CONFIG) return@firstOrNull false
        val bean = proxy.requireBean() as? ConfigBean ?: return@firstOrNull false
        bean.type == 0 && bean.name == autoName
    }
    if (existing != null) return

    val bean = ConfigBean().applyDefaultValues().apply {
        type = 0
        config = ""
        name = autoName
    }
    ProfileManager.createProfile(group.id, bean)
}

private suspend fun ensureDedicatedAutoSelectConfig(group: ProxyGroup) {
    val existing = SagerDatabase.proxyDao.getByGroup(group.id).firstOrNull { proxy ->
        if (proxy.type != ProxyEntity.TYPE_CONFIG) return@firstOrNull false
        val bean = proxy.requireBean() as? ConfigBean ?: return@firstOrNull false
        bean.type == 0 && bean.name == GroupManager.DEDICATED_CONFIG_NAME
    }
    if (existing != null) return

    val bean = ConfigBean().applyDefaultValues().apply {
        type = 0
        config = ""
        name = GroupManager.DEDICATED_CONFIG_NAME
    }
    ProfileManager.createProfile(group.id, bean)
}
