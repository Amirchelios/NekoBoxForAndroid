package io.nekohasekai.sagernet.database

import io.nekohasekai.sagernet.DEFAULT_SUBSCRIPTION_GROUP_NAME
import io.nekohasekai.sagernet.DEFAULT_SUBSCRIPTION_LINK
import io.nekohasekai.sagernet.GroupType
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.bg.SubscriptionUpdater
import io.nekohasekai.sagernet.ktx.applyDefaultValues
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import moe.matsuri.nb4a.proxy.config.ConfigBean

object GroupManager {

    private const val LEGACY_YOUTUBE_CONFIG_NAME = "باز کننده یوتویب و اینستاگرام"
    private const val LEGACY_DEDICATED_GROUP_NAME = "کانفیگ اختصاصی"
    private const val LEGACY_DEDICATED_SUBSCRIPTION_GITHUB_LINK =
        "https://raw.githubusercontent.com/Amirchelios/NG_manager_app/refs/heads/main/ml.txt?token=GHSAT0AAAAAADT4P36OTRU6MU7F7LDIVHJO2MAOJAA"
    private const val LEGACY_DEDICATED_SUBSCRIPTION_LINK =
        "https://drive.usercontent.google.com/u/0/uc?id=1JHaY3RHNHR2sYd_zu9CvNH6IdFv2ggec&export=download"
    private const val LEGACY_DEDICATED_CONFIG_NAME = "کانفیگ اختصاصی"
    private val ensureDefaultGroupMutex = Mutex()

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

    suspend fun ensureDefaultSubscriptionGroup(): ProxyGroup? = ensureDefaultGroupMutex.withLock {
        val groups = SagerDatabase.groupDao.allGroups()
        var existing = groups.firstOrNull { isProtectedGroup(it) }
            ?: groups.firstOrNull { it.type == GroupType.SUBSCRIPTION && it.name == DEFAULT_SUBSCRIPTION_GROUP_NAME }
        if (existing != null) {
            var changed = false
            if (existing.name != DEFAULT_SUBSCRIPTION_GROUP_NAME) {
                existing.name = DEFAULT_SUBSCRIPTION_GROUP_NAME
                changed = true
            }
            if (existing.type != GroupType.SUBSCRIPTION) {
                existing.type = GroupType.SUBSCRIPTION
                changed = true
            }
            if (existing.subscription == null) {
                existing.subscription = SubscriptionBean().applyDefaultValues()
                changed = true
            }
            if (!isDefaultSubscriptionGroup(existing)) {
                existing.subscription!!.link = DEFAULT_SUBSCRIPTION_LINK
                changed = true
            }
            if (changed) {
                SagerDatabase.groupDao.updateGroup(existing)
                iterator { groupUpdated(existing) }
                SubscriptionUpdater.reconfigureUpdater()
            }
            ensureDefaultAutoSelectConfig(existing)
            cleanupDuplicateDefaultSubscriptionGroups(existing)
            cleanupLegacyArtifacts()
            cleanupDuplicateSpecialConfigs(existing)
            return@withLock existing
        }
        val group = ProxyGroup(type = GroupType.SUBSCRIPTION).apply {
            name = DEFAULT_SUBSCRIPTION_GROUP_NAME
            subscription = SubscriptionBean().applyDefaultValues().also {
                it.link = DEFAULT_SUBSCRIPTION_LINK
            }
        }
        return@withLock createGroup(group).also {
            ensureDefaultAutoSelectConfig(it)
            cleanupDuplicateDefaultSubscriptionGroups(it)
            cleanupLegacyArtifacts()
            cleanupDuplicateSpecialConfigs(it)
        }
    }

    fun isProtectedGroup(group: ProxyGroup): Boolean {
        val link = group.subscription?.link?.trim().orEmpty()
        return group.type == GroupType.SUBSCRIPTION &&
            link.equals(DEFAULT_SUBSCRIPTION_LINK, ignoreCase = true)
    }

    fun isDefaultSubscriptionGroup(group: ProxyGroup): Boolean {
        if (group.type != GroupType.SUBSCRIPTION) return false
        val link = group.subscription?.link?.trim().orEmpty()
        return link.equals(DEFAULT_SUBSCRIPTION_LINK, ignoreCase = true)
    }

    private suspend fun cleanupLegacyArtifacts() {
        val legacyGroups = SagerDatabase.groupDao.allGroups().filter { group ->
            if (group.type != GroupType.SUBSCRIPTION) return@filter false
            val link = group.subscription?.link?.trim().orEmpty()
            link.equals(LEGACY_DEDICATED_SUBSCRIPTION_LINK, true) ||
                link.equals(LEGACY_DEDICATED_SUBSCRIPTION_GITHUB_LINK, true) ||
                group.name == LEGACY_DEDICATED_GROUP_NAME
        }
        if (legacyGroups.isNotEmpty()) {
            legacyGroups.forEach { group ->
                SagerDatabase.proxyDao.deleteByGroup(group.id)
                SagerDatabase.groupDao.deleteById(group.id)
                iterator { groupRemoved(group.id) }
            }
            SubscriptionUpdater.reconfigureUpdater()
        }
        val proxies = SagerDatabase.proxyDao.getAll()
        val legacyConfigs = proxies.filter { proxy ->
            if (proxy.type != ProxyEntity.TYPE_CONFIG) return@filter false
            val bean = proxy.requireBean() as? ConfigBean ?: return@filter false
            bean.type == 0 && (bean.name == LEGACY_YOUTUBE_CONFIG_NAME || bean.name == LEGACY_DEDICATED_CONFIG_NAME)
        }
        if (legacyConfigs.isNotEmpty()) {
            val affectedGroupIds = legacyConfigs.map { it.groupId }.toSet()
            legacyConfigs.forEach { SagerDatabase.proxyDao.deleteById(it.id) }
            affectedGroupIds.forEach { groupId ->
                rearrange(groupId)
                iterator { groupUpdated(groupId) }
            }
        }
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
        return isProtectedGroup(group) && isDefaultAutoSelectConfig(proxy)
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

    fun isRemovalBlocked(group: ProxyGroup, proxy: ProxyEntity): Boolean {
        return isProtectedProfile(group, proxy) || isAutoSelectConfig(proxy)
    }

    fun isRemovalBlocked(proxy: ProxyEntity): Boolean {
        val group = SagerDatabase.groupDao.getById(proxy.groupId) ?: return false
        return isRemovalBlocked(group, proxy)
    }

}

private suspend fun cleanupDuplicateDefaultSubscriptionGroups(keepGroup: ProxyGroup) {
    val duplicates = SagerDatabase.groupDao.allGroups().filter { group ->
        group.id != keepGroup.id &&
            group.type == GroupType.SUBSCRIPTION &&
            (group.name == DEFAULT_SUBSCRIPTION_GROUP_NAME || GroupManager.isDefaultSubscriptionGroup(group))
    }
    if (duplicates.isEmpty()) return

    for (duplicate in duplicates) {
        val proxies = SagerDatabase.proxyDao.getByGroup(duplicate.id)
        if (proxies.isNotEmpty()) {
            val nextOrderStart = (SagerDatabase.proxyDao.nextOrder(keepGroup.id) ?: 1L) - 1L
            proxies.forEachIndexed { index, proxy ->
                proxy.groupId = keepGroup.id
                proxy.userOrder = nextOrderStart + index + 1
            }
            SagerDatabase.proxyDao.updateProxy(proxies)
        }

        if (DataStore.selectedGroup == duplicate.id) {
            DataStore.selectedGroup = keepGroup.id
        }
        SagerDatabase.groupDao.deleteById(duplicate.id)
        GroupManager.iterator { groupRemoved(duplicate.id) }
    }
    GroupManager.rearrange(keepGroup.id)
    GroupManager.iterator { groupUpdated(keepGroup.id) }
    SubscriptionUpdater.reconfigureUpdater()
}

private suspend fun cleanupDuplicateSpecialConfigs(group: ProxyGroup) {
    val proxies = SagerDatabase.proxyDao.getByGroup(group.id)
    if (proxies.size < 2) return
    val autoName = SagerNet.application.getString(R.string.menu_auto_select)
    val targets = setOf(autoName)
    val candidates = proxies.filter { proxy ->
        proxy.type == ProxyEntity.TYPE_CONFIG &&
            (proxy.requireBean() as? ConfigBean)?.let { it.type == 0 && it.name in targets } == true
    }
    if (candidates.isEmpty()) return
    val byName = candidates.groupBy { (it.requireBean() as ConfigBean).name }
    var changed = false
    for ((_, list) in byName) {
        if (list.size <= 1) continue
        val keep = list
            .sortedWith(compareByDescending<ProxyEntity> {
                (it.requireBean() as? ConfigBean)?.config?.isNotBlank() == true
            }.thenBy { it.id })
            .first()
        list.filter { it.id != keep.id }.forEach { extra ->
            SagerDatabase.proxyDao.deleteById(extra.id)
            changed = true
        }
    }
    if (changed) {
        GroupManager.rearrange(group.id)
        GroupManager.iterator { groupUpdated(group.id) }
    }
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
