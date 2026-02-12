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

    private const val TIMEOUT_MS = 4500
    private const val MAX_ATTEMPTS = 3
    private const val FAST_TIMEOUT_MS = 1800
    private const val FAST_MAX_ATTEMPTS = 2
    private const val FAST_LIMIT = 40
    private const val MIN_SUCCESS_RATIO = 0.35
    private val testUrls = listOf(
        "https://cp.cloudflare.com/generate_204",
        "https://www.gstatic.com/generate_204",
        "https://www.msftconnecttest.com/connecttest.txt",
        "https://connectivitycheck.gstatic.com/generate_204",
        "https://detectportal.firefox.com/success.txt",
        "https://speed.cloudflare.com/__down?bytes=200000"
    )

    private data class ProbeSnapshot(
        val score: Int,
        val successCount: Int,
        val jitter: Int,
        val worst: Int,
    )

    private data class ProfileEvaluation(
        val profile: ProxyEntity,
        val score: Int?,
        val successRatio: Double,
        val jitter: Int,
        val worst: Int,
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

        val evaluations = evaluateProfiles(profiles, TIMEOUT_MS, MAX_ATTEMPTS)
        if (evaluations.isEmpty()) return null
        evaluations.forEach { updateHealthState(it) }

        val valid = evaluations.filter { it.score != null }.sortedBy { it.score }
        if (valid.isEmpty()) return null

        val best = valid.first()
        val orderedIds = valid.map { it.profile.id } + evaluations
            .filterNot { it.score != null }
            .map { it.profile.id }
        DataStore.setSmartPreferredProxy(groupId, best.profile.id)
        DataStore.setSmartPreferredOrder(groupId, orderedIds)
        DataStore.markSmartPreferredOrderDirty(groupId)

        evaluations.forEach { ev ->
            if (ev.score != null) {
                ev.profile.status = 1
                ev.profile.ping = ev.score
                ev.profile.error = null
            } else {
                ev.profile.status = 2
                ev.profile.error = "unstable route"
            }
        }
        SagerDatabase.proxyDao.updateProxy(evaluations.map { it.profile })

        val update = profiles.associateBy { it.id }.toMutableMap()
        var order = 1L
        orderedIds.forEach { id ->
            update[id]?.let {
                it.userOrder = order++
            }
        }
        SagerDatabase.proxyDao.updateProxy(update.values.toList())
        return best.profile.id
    }

    suspend fun selectBestFast(groupId: Long): Long? {
        val profiles = SagerDatabase.proxyDao.getByGroup(groupId)
            .filterNot { it.type == TYPE_CONFIG }
        if (profiles.isEmpty()) return null

        val cachedOrder = DataStore.getSmartPreferredOrder(groupId)
        val profileMap = profiles.associateBy { it.id }
        val ordered = if (cachedOrder.isNotEmpty()) {
            cachedOrder.mapNotNull { profileMap[it] } + profiles.filterNot { cachedOrder.contains(it.id) }
        } else {
            profiles
        }
        val candidates = ordered.take(FAST_LIMIT)

        val evaluations = evaluateProfiles(candidates, FAST_TIMEOUT_MS, FAST_MAX_ATTEMPTS)
        if (evaluations.isEmpty()) return null
        evaluations.forEach { updateHealthState(it) }

        val sorted = evaluations.filter { it.score != null }.sortedBy { it.score }
        val best = sorted.firstOrNull() ?: return null
        val orderedIds = sorted.map { it.profile.id } + evaluations
            .filterNot { it.score != null }
            .map { it.profile.id }
        DataStore.setSmartPreferredProxy(groupId, best.profile.id)
        DataStore.setSmartPreferredOrder(groupId, orderedIds)
        DataStore.markSmartPreferredOrderDirty(groupId)
        return best.profile.id
    }

    private suspend fun evaluateProfiles(
        profiles: List<ProxyEntity>,
        timeoutMs: Int,
        attempts: Int,
    ): List<ProfileEvaluation> {
        val concurrency = DataStore.connectionTestConcurrent.coerceAtLeast(1)
        val semaphore = Semaphore(concurrency)
        return coroutineScope {
            profiles.map { profile ->
                async {
                    semaphore.withPermit {
                        evaluateProfile(profile, timeoutMs, attempts)
                    }
                }
            }.awaitAll().filterNotNull()
        }
    }

    private suspend fun evaluateProfile(
        profile: ProxyEntity,
        timeoutMs: Int,
        attempts: Int,
    ): ProfileEvaluation? {
        return try {
            val snapshots = mutableListOf<ProbeSnapshot>()
            repeat(attempts) {
                testOnce(profile, timeoutMs)?.let { snapshots += it }
            }

            val totalProbes = (attempts * testUrls.size).coerceAtLeast(1)
            val successCount = snapshots.sumOf { it.successCount }
            val successRatio = successCount.toDouble() / totalProbes.toDouble()
            val jitter = snapshots.map { it.jitter }.average().toInt().coerceAtLeast(0)
            val worst = snapshots.maxOfOrNull { it.worst } ?: 0
            val baseScore = snapshots.minOfOrNull { it.score }
            val rawPenalty = buildPenalty(successRatio, jitter, worst, baseScore)
            val healthPenalty = DataStore.getSmartHealthPenalty(profile.id)
            val failStreak = DataStore.getSmartFailureStreak(profile.id)
            val streakPenalty = failStreak * 45
            val finalScore = if (baseScore == null || successRatio < MIN_SUCCESS_RATIO) {
                null
            } else {
                (baseScore + rawPenalty + healthPenalty + streakPenalty).coerceAtLeast(1)
            }
            ProfileEvaluation(
                profile = profile,
                score = finalScore,
                successRatio = successRatio,
                jitter = jitter,
                worst = worst,
            )
        } catch (e: Exception) {
            Logs.w(e.readableMessage)
            null
        }
    }

    private suspend fun testOnce(profile: ProxyEntity, timeoutMs: Int): ProbeSnapshot? {
        val successes = mutableListOf<Int>()
        val minRequired = (testUrls.size / 2).coerceAtLeast(1)
        var remaining = testUrls.size
        for (url in testUrls) {
            remaining -= 1
            val elapsed = runCatching { TestInstance(profile, url, timeoutMs).doTest() }.getOrNull()
            if (elapsed != null && elapsed > 0) {
                successes += elapsed
            }
            if (successes.size + remaining < minRequired) {
                return null
            }
        }
        if (successes.size < minRequired) return null

        val sorted = successes.sorted()
        val bestSamples = sorted.take(minOf(3, sorted.size))
        val score = (bestSamples.sum().toDouble() / bestSamples.size).toInt().coerceAtLeast(1)
        val jitter = (sorted.last() - sorted.first()).coerceAtLeast(0)
        val worst = sorted.last()
        return ProbeSnapshot(
            score = score,
            successCount = successes.size,
            jitter = jitter,
            worst = worst,
        )
    }

    private fun buildPenalty(
        successRatio: Double,
        jitter: Int,
        worst: Int,
        baseScore: Int?,
    ): Int {
        val failPenalty = ((1.0 - successRatio).coerceIn(0.0, 1.0) * 900.0).toInt()
        val jitterPenalty = (jitter * 2).coerceAtMost(260)
        val worstPenalty = if (baseScore == null || worst <= 0) {
            160
        } else {
            ((worst - baseScore) / 2).coerceIn(0, 260)
        }
        return failPenalty + jitterPenalty + worstPenalty
    }

    private fun updateHealthState(result: ProfileEvaluation) {
        val profileId = result.profile.id
        val oldPenalty = DataStore.getSmartHealthPenalty(profileId)
        val oldStreak = DataStore.getSmartFailureStreak(profileId)
        if (result.score == null) {
            DataStore.setSmartLastScore(profileId, -1)
            val newStreak = (oldStreak + 1).coerceAtMost(20)
            val bump = (220 + newStreak * 30).coerceAtMost(700)
            DataStore.setSmartFailureStreak(profileId, newStreak)
            DataStore.setSmartHealthPenalty(profileId, oldPenalty + bump)
            return
        }

        DataStore.setSmartLastScore(profileId, result.score)
        val stable = result.successRatio >= 0.80 && result.jitter <= 120
        val newStreak = (oldStreak - 2).coerceAtLeast(0)
        val baseDrop = if (stable) 220 else 120
        val softness = if (result.successRatio < 0.65) 60 else 0
        DataStore.setSmartFailureStreak(profileId, newStreak)
        DataStore.setSmartHealthPenalty(profileId, oldPenalty - baseDrop + softness)
    }
}
