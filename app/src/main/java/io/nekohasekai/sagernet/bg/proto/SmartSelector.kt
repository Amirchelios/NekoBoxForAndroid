package io.nekohasekai.sagernet.bg.proto

import io.nekohasekai.sagernet.GroupOrder
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.database.ProxyEntity.Companion.TYPE_CONFIG
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.readableMessage
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit

object SmartSelector {

    private const val TIMEOUT_MS = 4000
    private const val MAX_ATTEMPTS = 2
    private val testUrls = listOf(
        "https://www.youtube.com/generate_204",
        "https://www.youtube.com/",
        "https://i.instagram.com/",
        "https://www.instagram.com/"
    )

    fun applyCachedOrder(groupId: Long) {
        val group = SagerDatabase.groupDao.getById(groupId) ?: return
        val cachedOrder = DataStore.getSmartPreferredOrder(groupId)
        if (cachedOrder.isEmpty()) return
        if (group.order != GroupOrder.ORIGIN) return

        val profiles = SagerDatabase.proxyDao.getByGroup(groupId)
            .filterNot { it.type == TYPE_CONFIG }
        if (profiles.isEmpty()) return

        val profileMap = profiles.associateBy { it.id }.toMutableMap()
        val orderedIds = cachedOrder.filter { profileMap.containsKey(it) }
        val remaining = profiles.filterNot { orderedIds.contains(it.id) }.map { it.id }
        val finalIds = orderedIds + remaining

        var order = 1L
        finalIds.forEach { id ->
            profileMap[id]?.let { it.userOrder = order++ }
        }
        SagerDatabase.proxyDao.updateProxy(profileMap.values.toList())
    }

    suspend fun selectBest(groupId: Long): Long? {
        val group = SagerDatabase.groupDao.getById(groupId) ?: return null
        val profiles = SagerDatabase.proxyDao.getByGroup(groupId)
            .filterNot { it.type == TYPE_CONFIG }
        if (profiles.isEmpty()) return null

        val concurrency = DataStore.connectionTestConcurrent.coerceAtLeast(1)
        val semaphore = Semaphore(concurrency)
        val results = coroutineScope {
            profiles.map { profile ->
                async {
                    semaphore.withPermit {
                        val score = testProfile(profile)
                        if (score != null) {
                            profile to score
                        } else {
                            null
                        }
                    }
                }
            }.awaitAll().filterNotNull()
        }

        if (results.isEmpty()) return null

        val sortedResults = results.sortedBy { it.second }
        val best = sortedResults.firstOrNull() ?: return null
        DataStore.setSmartPreferredProxy(groupId, best.first.id)
        DataStore.setSmartPreferredOrder(groupId, sortedResults.map { it.first.id })

        results.forEach { (profile, score) ->
            profile.status = 1
            profile.ping = score
            profile.error = null
        }
        SagerDatabase.proxyDao.updateProxy(results.map { it.first })

        if (group.order == GroupOrder.ORIGIN) {
            val sortedIds = sortedResults.map { it.first.id }
            val remaining = profiles.filterNot { sortedIds.contains(it.id) }.map { it.id }
            val orderedIds = sortedIds + remaining
            val update = profiles.associateBy { it.id }.toMutableMap()
            var order = 1L
            orderedIds.forEach { id ->
                update[id]?.let {
                    it.userOrder = order++
                }
            }
            SagerDatabase.proxyDao.updateProxy(update.values.toList())
        }
        return best.first.id
    }

    private suspend fun testProfile(profile: ProxyEntity): Int? {
        var best: Int? = null
        repeat(MAX_ATTEMPTS) {
            val score = testOnce(profile)
            if (score != null) {
                if (best == null || score < best!!) {
                    best = score
                }
            }
        }
        return best
    }

    private suspend fun testOnce(profile: ProxyEntity): Int? {
        return try {
            var total = 0
            for (url in testUrls) {
                val elapsed = TestInstance(profile, url, TIMEOUT_MS).doTest()
                if (elapsed <= 0) return null
                total += elapsed
            }
            total
        } catch (e: Exception) {
            Logs.w(e.readableMessage)
            null
        }
    }
}
