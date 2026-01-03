package io.nekohasekai.sagernet.bg.proto

import io.nekohasekai.sagernet.GroupOrder
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.database.ProxyEntity.Companion.TYPE_CONFIG
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.readableMessage

object SmartSelector {

    private const val TIMEOUT_MS = 2000
    private const val MAX_ATTEMPTS = 2
    private val testUrls = listOf(
        "https://www.youtube.com/generate_204",
        "https://i.instagram.com/"
    )

    suspend fun selectBest(groupId: Long): Long? {
        val group = SagerDatabase.groupDao.getById(groupId) ?: return null
        val profiles = SagerDatabase.proxyDao.getByGroup(groupId)
            .filterNot { it.type == TYPE_CONFIG }
        if (profiles.isEmpty()) return null

        val results = mutableListOf<Pair<ProxyEntity, Int>>()
        for (profile in profiles) {
            val score = testProfile(profile)
            if (score != null) {
                results.add(profile to score)
            }
        }

        if (results.isEmpty()) return null

        val best = results.minByOrNull { it.second } ?: return null
        DataStore.setSmartPreferredProxy(groupId, best.first.id)

        results.forEach { (profile, score) ->
            profile.status = 1
            profile.ping = score
            profile.error = null
        }
        SagerDatabase.proxyDao.updateProxy(results.map { it.first })

        if (group.order == GroupOrder.ORIGIN) {
            val sortedIds = results.sortedBy { it.second }.map { it.first.id }
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
