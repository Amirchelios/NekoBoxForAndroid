package io.nekohasekai.sagernet.database

import io.nekohasekai.sagernet.DEFAULT_SUBSCRIPTION_GROUP_NAME
import io.nekohasekai.sagernet.DEFAULT_SUBSCRIPTION_LINK
import io.nekohasekai.sagernet.GroupType
import io.nekohasekai.sagernet.bg.SubscriptionUpdater
import io.nekohasekai.sagernet.ktx.applyDefaultValues

object GroupManager {

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
            return existing
        }
        val group = ProxyGroup(type = GroupType.SUBSCRIPTION).apply {
            name = DEFAULT_SUBSCRIPTION_GROUP_NAME
            subscription = SubscriptionBean().applyDefaultValues().also {
                it.link = DEFAULT_SUBSCRIPTION_LINK
            }
        }
        return createGroup(group)
    }

    fun isProtectedGroup(group: ProxyGroup): Boolean {
        val link = group.subscription?.link?.trim().orEmpty()
        return group.type == GroupType.SUBSCRIPTION &&
            link.equals(DEFAULT_SUBSCRIPTION_LINK, ignoreCase = true)
    }

}
