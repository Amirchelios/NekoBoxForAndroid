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
        val bandwidthKbps: Int,
    )

    private data class ProfileEvaluation(
        val profile: ProxyEntity,
        val score: Int?,
        val successRatio: Double,
        val jitter: Int,
        val worst: Int,
        val bandwidthKbps: Int,
        val transportClass: TransportClass,
    )

    private enum class TransportClass(val key: String) {
        TLS("tls"),
        PLAIN("plain"),
        MIXED("mixed"),
    }

    private enum class SmartMode {
        GAMING,
        STREAMING,
        DOWNLOAD,
        BALANCED,
        MANUAL,
    }

    private data class ModePolicy(
        val topCount: Int,
        val verifyAttempts: Int,
        val verifyTimeoutMs: Int,
        val minSuccessRatio: Double,
        val preferBandwidth: Boolean,
        val probeBiasMs: Int,
        val quarantineBoost: Int,
        val hysteresisBonus: Int,
    )

    private fun modePolicy(): ModePolicy {
        return when (smartMode()) {
            SmartMode.GAMING -> ModePolicy(
                topCount = 3,
                verifyAttempts = 3,
                verifyTimeoutMs = 2400,
                minSuccessRatio = 0.55,
                preferBandwidth = false,
                probeBiasMs = -200,
                quarantineBoost = 12,
                hysteresisBonus = 260,
            )
            SmartMode.STREAMING -> ModePolicy(
                topCount = 4,
                verifyAttempts = 3,
                verifyTimeoutMs = 2600,
                minSuccessRatio = 0.60,
                preferBandwidth = true,
                probeBiasMs = 0,
                quarantineBoost = 18,
                hysteresisBonus = 300,
            )
            SmartMode.DOWNLOAD -> ModePolicy(
                topCount = 5,
                verifyAttempts = 2,
                verifyTimeoutMs = 3000,
                minSuccessRatio = 0.45,
                preferBandwidth = true,
                probeBiasMs = 150,
                quarantineBoost = 20,
                hysteresisBonus = 220,
            )
            SmartMode.MANUAL,
            SmartMode.BALANCED -> ModePolicy(
                topCount = 3,
                verifyAttempts = 3,
                verifyTimeoutMs = 2800,
                minSuccessRatio = 0.50,
                preferBandwidth = true,
                probeBiasMs = 0,
                quarantineBoost = 16,
                hysteresisBonus = 280,
            )
        }
    }

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

    suspend fun selectBest(groupId: Long, scope: String = "default"): Long? {
        val group = SagerDatabase.groupDao.getById(groupId) ?: return null
        val profiles = SagerDatabase.proxyDao.getByGroup(groupId)
            .filterNot { it.type == TYPE_CONFIG }
        if (profiles.isEmpty()) return null

        val policy = modePolicy()
        val candidates = filterQuarantined(profiles)
        val timeoutMs = (TIMEOUT_MS + policy.probeBiasMs).coerceIn(1_500, 6_000)
        val evaluations = evaluateProfiles(candidates, groupId, scope, timeoutMs, MAX_ATTEMPTS)
        if (evaluations.isEmpty()) return null
        evaluations.forEach { updateHealthState(groupId, scope, it) }

        val valid = refineWithThroughput(evaluations.filter { it.score != null })
            .sortedWith(compareBy<ProfileEvaluation> {
                stabilityAdjustedScore(it, DataStore.getSmartPreferredProxy(groupId))
            }.thenBy { modeAdjustedScore(it) }
                .thenByDescending { it.bandwidthKbps })
        if (valid.isEmpty()) return null

        val shortlist = valid.take(policy.topCount.coerceAtLeast(1))
        val verified = pickVerifiedCandidate(shortlist, scope, policy) ?: shortlist.first()
        if (verified.score == null || verified.successRatio < policy.minSuccessRatio) {
            return shortlist.firstOrNull()?.profile?.id
        }

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

        val fallbackIds = evaluations.filterNot { it.score != null }.map { it.profile.id }
        return commitCandidate(groupId, verified, valid, fallbackIds)
    }

    suspend fun selectBestFast(groupId: Long, scope: String = "default"): Long? {
        return selectTopFast(groupId, 1, scope).firstOrNull()
    }

    suspend fun selectTopFast(groupId: Long, limit: Int, scope: String = "default"): List<Long> {
        val profiles = SagerDatabase.proxyDao.getByGroup(groupId)
            .filterNot { it.type == TYPE_CONFIG }
        if (profiles.isEmpty()) return emptyList()

        val policy = modePolicy()
        val fastTimeoutMs = (FAST_TIMEOUT_MS + policy.probeBiasMs / 2).coerceIn(1_000, 4_000)
        val cachedOrder = DataStore.getSmartPreferredOrder(groupId)
        val profileMap = profiles.associateBy { it.id }
        val ordered = if (cachedOrder.isNotEmpty()) {
            cachedOrder.mapNotNull { profileMap[it] } + profiles.filterNot { cachedOrder.contains(it.id) }
        } else {
            profiles
        }
        val available = filterQuarantined(ordered)
        val candidates = available.take((FAST_LIMIT * 2).coerceAtMost(available.size))
            .sortedByDescending { fastPriorityScore(it) }
            .take(FAST_LIMIT)

        val evaluations = evaluateProfiles(candidates, groupId, scope, fastTimeoutMs, FAST_MAX_ATTEMPTS)
        if (evaluations.isEmpty()) return emptyList()
        evaluations.forEach { updateHealthState(groupId, scope, it) }

        val sorted = refineWithThroughput(evaluations.filter { it.score != null })
            .sortedWith(compareBy<ProfileEvaluation> {
                stabilityAdjustedScore(it, DataStore.getSmartPreferredProxy(groupId))
            }.thenBy { modeAdjustedScore(it) }
                .thenByDescending { it.bandwidthKbps })
        if (sorted.isEmpty()) return emptyList()
        val shortlist = sorted.take(policy.topCount.coerceAtLeast(1))
        val verified = pickVerifiedCandidate(shortlist, scope, policy) ?: shortlist.first()
        val fallbackIds = evaluations.filterNot { it.score != null }.map { it.profile.id }
        val committedId = commitCandidate(groupId, verified, sorted, fallbackIds)
        return (listOf(committedId) + sorted.filterNot { it.profile.id == committedId }.map { it.profile.id } + fallbackIds)
            .take(limit.coerceAtLeast(1))
    }

    private fun fastPriorityScore(profile: ProxyEntity): Long {
        val lastScore = DataStore.getSmartLastScore(profile.id)
        val bandwidth = DataStore.getSmartLastBandwidthKbps(profile.id).coerceAtLeast(0)
        val failStreak = DataStore.getSmartFailureStreak(profile.id)
        val healthPenalty = DataStore.getSmartHealthPenalty(profile.id)
        val quality = DataStore.getSmartQualityScore(profile.id)
        val quarantinePenalty = if (DataStore.isSmartQuarantined(profile.id)) 12_000L else 0L

        val latencyScore = if (lastScore > 0) {
            ((20_000 - lastScore.coerceAtMost(20_000)).toLong() * 5L)
        } else {
            0L
        }
        val throughputScore = bandwidth.coerceAtMost(80_000).toLong() * 2L
        val failPenalty = failStreak.toLong() * 1_500L
        val healthPenaltyScore = healthPenalty.toLong() * 4L
        return latencyScore + throughputScore + quality.toLong() * 600L -
            failPenalty - healthPenaltyScore - quarantinePenalty
    }

    private fun smartMode(): SmartMode {
        return when (DataStore.normalizedSmartProfilePreset()) {
            "gaming" -> SmartMode.GAMING
            "streaming" -> SmartMode.STREAMING
            "download" -> SmartMode.DOWNLOAD
            "manual" -> SmartMode.MANUAL
            else -> SmartMode.BALANCED
        }
    }

    private fun preferredProxyBias(profileId: Long, preferredId: Long): Int {
        if (profileId <= 0L || preferredId <= 0L) return 0
        return if (profileId == preferredId) 220 else 0
    }

    private fun recencyBias(profileId: Long): Int {
        val observedAt = DataStore.getSmartLastObservedAt(profileId)
        if (observedAt <= 0L) return 0
        val ageMs = System.currentTimeMillis() - observedAt
        return when {
            ageMs <= 2 * 60_000L -> 12
            ageMs <= 10 * 60_000L -> 8
            ageMs <= 30 * 60_000L -> 4
            else -> 0
        }
    }

    private fun switchChurnPenalty(profileId: Long): Int {
        return (DataStore.getSmartRecentSwitchCount(profileId) * 4).coerceAtMost(60)
    }

    private fun stabilityAdjustedScore(ev: ProfileEvaluation, preferredId: Long): Int {
        val base = modeAdjustedScore(ev)
        val bias = preferredProxyBias(ev.profile.id, preferredId) + recencyBias(ev.profile.id)
        val churnPenalty = switchChurnPenalty(ev.profile.id)
        val policy = modePolicy()
        val hysteresis = if (ev.profile.id == preferredId) policy.hysteresisBonus else 0
        val quarantineBonus = if (DataStore.isSmartQuarantined(ev.profile.id)) policy.quarantineBoost else 0
        return (base - bias - hysteresis + churnPenalty + quarantineBonus).coerceAtLeast(1)
    }

    private suspend fun verifyCandidate(
        profile: ProxyEntity,
        scope: String,
        policy: ModePolicy,
    ): ProfileEvaluation? {
        val evaluated = evaluateProfile(profile, profile.groupId, scope, policy.verifyTimeoutMs, policy.verifyAttempts)
            ?: return null
        val refined = refineWithThroughput(listOf(evaluated)).firstOrNull() ?: evaluated
        return refined
    }

    private fun commitCandidate(
        groupId: Long,
        candidate: ProfileEvaluation,
        fullOrder: List<ProfileEvaluation>,
        fallbackIds: List<Long>,
    ): Long {
        val orderedIds = listOf(candidate.profile.id) + fullOrder
            .filterNot { it.profile.id == candidate.profile.id }
            .map { it.profile.id } + fallbackIds
        DataStore.setSmartPreferredProxy(groupId, candidate.profile.id)
        DataStore.setSmartPreferredOrder(groupId, orderedIds)
        DataStore.markSmartPreferredOrderDirty(groupId)
        DataStore.clearSmartPreferredOrderDirty(groupId)

        val update = SagerDatabase.proxyDao.getByGroup(groupId).associateBy { it.id }.toMutableMap()
        var order = 1L
        orderedIds.forEach { id ->
            update[id]?.let { it.userOrder = order++ }
        }
        SagerDatabase.proxyDao.updateProxy(update.values.toList())
        return candidate.profile.id
    }

    private suspend fun pickVerifiedCandidate(
        shortlist: List<ProfileEvaluation>,
        scope: String,
        policy: ModePolicy,
    ): ProfileEvaluation? {
        for (candidate in shortlist) {
            val checked = verifyCandidate(candidate.profile, scope, policy) ?: continue
            if (checked.score != null && checked.successRatio >= policy.minSuccessRatio) {
                return checked
            }
        }
        return null
    }

    private fun filterQuarantined(profiles: List<ProxyEntity>): List<ProxyEntity> {
        if (!DataStore.smartQuarantineEnabled) return profiles
        val active = profiles.filterNot { DataStore.isSmartQuarantined(it.id) }
        return active.ifEmpty { profiles }
    }

    private fun modeAdjustedScore(ev: ProfileEvaluation): Int {
        val base = ev.score ?: Int.MAX_VALUE
        if (base == Int.MAX_VALUE) return base
        val qualityPenalty = (100 - DataStore.getSmartQualityScore(ev.profile.id)).coerceIn(0, 100) * 3
        val policy = modePolicy()
        val bandwidthBonus = if (policy.preferBandwidth) {
            bandwidthScoreBonus(ev.bandwidthKbps)
        } else {
            bandwidthScoreBonus(ev.bandwidthKbps) / 2
        }
        return when (smartMode()) {
            SmartMode.GAMING -> {
                base + ev.jitter.coerceAtMost(500) * 2 +
                    ((1.0 - ev.successRatio).coerceIn(0.0, 1.0) * 700.0).toInt() +
                    qualityPenalty -
                    (bandwidthBonus / 3)
            }
            SmartMode.STREAMING -> {
                base + ev.jitter.coerceAtMost(500) +
                    ((1.0 - ev.successRatio).coerceIn(0.0, 1.0) * 1000.0).toInt() -
                    bandwidthBonus * 2 +
                    qualityPenalty
            }
            SmartMode.DOWNLOAD -> {
                base - bandwidthBonus * 3 +
                    ((1.0 - ev.successRatio).coerceIn(0.0, 1.0) * 450.0).toInt() +
                    qualityPenalty / 2
            }
            SmartMode.MANUAL,
            SmartMode.BALANCED -> {
                base + ev.jitter.coerceAtMost(350) +
                    ((1.0 - ev.successRatio).coerceIn(0.0, 1.0) * 650.0).toInt() -
                    bandwidthBonus +
                    qualityPenalty
            }
        }.coerceAtLeast(1)
    }

    private suspend fun evaluateProfiles(
        profiles: List<ProxyEntity>,
        groupId: Long,
        scope: String,
        timeoutMs: Int,
        attempts: Int,
    ): List<ProfileEvaluation> {
        val concurrency = DataStore.connectionTestConcurrent.coerceAtLeast(1)
        val semaphore = Semaphore(concurrency)
        return coroutineScope {
            profiles.map { profile ->
                async {
                    semaphore.withPermit {
                        evaluateProfile(profile, groupId, scope, timeoutMs, attempts)
                    }
                }
            }.awaitAll().filterNotNull()
        }
    }

    private suspend fun evaluateProfile(
        profile: ProxyEntity,
        groupId: Long,
        scope: String,
        timeoutMs: Int,
        attempts: Int,
    ): ProfileEvaluation? {
        return try {
            val transportClass = detectTransportClass(profile)
            val snapshots = mutableListOf<ProbeSnapshot>()
            repeat(attempts) {
                testOnce(profile, timeoutMs)?.let { snapshots += it }
            }

            val totalProbes = (attempts * testUrls.size).coerceAtLeast(1)
            val successCount = snapshots.sumOf { it.successCount }
            val successRatio = successCount.toDouble() / totalProbes.toDouble()
            val jitter = snapshots.map { it.jitter }.average().toInt().coerceAtLeast(0)
            val worst = snapshots.maxOfOrNull { it.worst } ?: 0
            val bandwidthKbps = snapshots.map { it.bandwidthKbps }.filter { it > 0 }
                .average().toInt().coerceAtLeast(0)
            val baseScore = snapshots.minOfOrNull { it.score }
            val rawPenalty = buildPenalty(successRatio, jitter, worst, baseScore, bandwidthKbps)
            val healthPenalty = DataStore.getSmartHealthPenalty(profile.id)
            val failStreak = DataStore.getSmartFailureStreak(profile.id)
            val streakPenalty = failStreak * 45
            val transportPenalty = if (DataStore.smartAdaptiveTransportEnabled) {
                DataStore.getSmartTransportPenalty(scope, groupId, transportClass.key)
            } else {
                0
            }
            val finalScore = if (baseScore == null || successRatio < MIN_SUCCESS_RATIO) {
                null
            } else {
                (baseScore + rawPenalty + healthPenalty + streakPenalty + transportPenalty)
                    .coerceAtLeast(1)
            }
            DataStore.setSmartLastObservedAt(profile.id, System.currentTimeMillis())
            ProfileEvaluation(
                profile = profile,
                score = finalScore,
                successRatio = successRatio,
                jitter = jitter,
                worst = worst,
                bandwidthKbps = bandwidthKbps,
                transportClass = transportClass,
            )
        } catch (e: Exception) {
            Logs.w(e.readableMessage)
            null
        }
    }

    private suspend fun refineWithThroughput(valid: List<ProfileEvaluation>): List<ProfileEvaluation> {
        if (!DataStore.smartSpeedRefineEnabled) return valid
        if (valid.size < 2) return valid
        val topN = DataStore.smartSpeedRefineTopN.coerceIn(2, 8)
        val timeoutMs = DataStore.smartSpeedRefineTimeoutMs.coerceIn(1200, 7000)
        val url = DataStore.parallelUrl.ifBlank { "https://speed.cloudflare.com/__down?bytes=800000" }
        val targets = valid.take(topN)
        val measured = coroutineScope {
            targets.map { ev ->
                async {
                    val elapsed = runCatching { TestInstance(ev.profile, url, timeoutMs).doTest() }.getOrNull()
                    val kbps = elapsed?.let { estimateBandwidthKbps(url, it) } ?: 0
                    if (kbps > 0) {
                        DataStore.setSmartLastBandwidthKbps(ev.profile.id, kbps)
                    }
                    ev.profile.id to kbps
                }
            }.awaitAll()
        }.toMap()

        if (measured.values.none { it > 0 }) return valid
        return valid.sortedWith(
            compareBy<ProfileEvaluation> {
                val base = it.score ?: Int.MAX_VALUE
                val measuredKbps = measured[it.profile.id] ?: 0
                val blended = maxOf(it.bandwidthKbps, measuredKbps)
                base - bandwidthScoreBonus(blended)
            }.thenBy { it.score ?: Int.MAX_VALUE }
                .thenByDescending { maxOf(it.bandwidthKbps, measured[it.profile.id] ?: 0) }
        )
    }

    private fun bandwidthScoreBonus(kbps: Int): Int {
        return when {
            kbps >= 30_000 -> 220
            kbps >= 20_000 -> 170
            kbps >= 12_000 -> 120
            kbps >= 7_000 -> 70
            kbps >= 3_000 -> 30
            else -> 0
        }
    }

    private suspend fun testOnce(profile: ProxyEntity, timeoutMs: Int): ProbeSnapshot? {
        val successes = mutableListOf<Int>()
        val bandwidthSamples = mutableListOf<Int>()
        val minRequired = (testUrls.size / 2).coerceAtLeast(1)
        var remaining = testUrls.size
        for (url in testUrls) {
            remaining -= 1
            val elapsed = runCatching { TestInstance(profile, url, timeoutMs).doTest() }.getOrNull()
            if (elapsed != null && elapsed > 0) {
                successes += elapsed
                estimateBandwidthKbps(url, elapsed)?.let { bandwidthSamples += it }
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
            bandwidthKbps = bandwidthSamples.average().toInt().coerceAtLeast(0),
        )
    }

    private fun estimateBandwidthKbps(url: String, elapsedMs: Int): Int? {
        if (elapsedMs <= 0) return null
        val bytes = "__down?bytes=".let { key ->
            val idx = url.indexOf(key)
            if (idx < 0) return null
            url.substring(idx + key.length).takeWhile { it.isDigit() }.toLongOrNull() ?: return null
        }
        if (bytes <= 0L) return null
        val kbps = (bytes * 8L / elapsedMs.toLong()).coerceAtMost(5_000_000L)
        return kbps.toInt().coerceAtLeast(1)
    }

    private fun buildPenalty(
        successRatio: Double,
        jitter: Int,
        worst: Int,
        baseScore: Int?,
        bandwidthKbps: Int,
    ): Int {
        val failPenalty = ((1.0 - successRatio).coerceIn(0.0, 1.0) * 900.0).toInt()
        val jitterPenalty = (jitter * 2).coerceAtMost(260)
        val worstPenalty = if (baseScore == null || worst <= 0) {
            160
        } else {
            ((worst - baseScore) / 2).coerceIn(0, 260)
        }
        val bandwidthBonus = when {
            bandwidthKbps >= 24_000 -> 220
            bandwidthKbps >= 16_000 -> 170
            bandwidthKbps >= 10_000 -> 120
            bandwidthKbps >= 6_000 -> 70
            bandwidthKbps >= 3_000 -> 30
            else -> 0
        }
        return (failPenalty + jitterPenalty + worstPenalty - bandwidthBonus).coerceAtLeast(0)
    }

    private fun updateHealthState(groupId: Long, scope: String, result: ProfileEvaluation) {
        val profileId = result.profile.id
        val oldPenalty = DataStore.getSmartHealthPenalty(profileId)
        val oldStreak = DataStore.getSmartFailureStreak(profileId)
        if (result.score == null) {
            DataStore.setSmartFailureCount(profileId, DataStore.getSmartFailureCount(profileId) + 1)
            DataStore.setSmartLastFailureAt(profileId, System.currentTimeMillis())
            DataStore.setSmartLastScore(profileId, -1)
            DataStore.setSmartLastBandwidthKbps(profileId, -1)
            DataStore.bumpSmartRecentSwitchCount(profileId)
            val newStreak = (oldStreak + 1).coerceAtMost(20)
            val bump = (220 + newStreak * 30).coerceAtMost(700)
            DataStore.setSmartFailureStreak(profileId, newStreak)
            DataStore.setSmartHealthPenalty(profileId, oldPenalty + bump)
            when {
                newStreak >= 6 -> DataStore.quarantineSmartProfile(
                    profileId,
                    DataStore.smartQuarantineLongMin
                )
                newStreak >= 4 -> DataStore.quarantineSmartProfile(
                    profileId,
                    DataStore.smartQuarantineMediumMin
                )
                newStreak >= 2 -> DataStore.quarantineSmartProfile(
                    profileId,
                    DataStore.smartQuarantineShortMin
                )
            }
            if (DataStore.smartAdaptiveTransportEnabled) {
                val step = DataStore.smartTransportPenaltyStep.coerceIn(20, 600)
                DataStore.adjustSmartTransportPenalty(scope, groupId, result.transportClass.key, step)
            }
            return
        }

        DataStore.setSmartSuccessCount(profileId, DataStore.getSmartSuccessCount(profileId) + 1)
        DataStore.setSmartLastSuccessAt(profileId, System.currentTimeMillis())
        DataStore.setSmartLastScore(profileId, result.score)
        DataStore.setSmartLastBandwidthKbps(profileId, result.bandwidthKbps)
        val stable = result.successRatio >= 0.80 && result.jitter <= 120
        val newStreak = (oldStreak - 2).coerceAtLeast(0)
        val baseDrop = if (stable) 220 else 120
        val softness = if (result.successRatio < 0.65) 60 else 0
        DataStore.setSmartFailureStreak(profileId, newStreak)
        DataStore.setSmartHealthPenalty(profileId, oldPenalty - baseDrop + softness)
        DataStore.decaySmartRecentSwitchCount(profileId, if (stable) 2 else 1)
        if (stable || newStreak == 0) {
            DataStore.clearSmartQuarantine(profileId)
        }
        if (DataStore.smartAdaptiveTransportEnabled) {
            val decay = DataStore.smartTransportPenaltyDecay.coerceIn(10, 400)
            DataStore.decaySmartTransportPenalty(scope, groupId, result.transportClass.key, decay)
        }
    }

    private fun detectTransportClass(profile: ProxyEntity): TransportClass {
        return when (profile.type) {
            ProxyEntity.TYPE_TROJAN,
            ProxyEntity.TYPE_TROJAN_GO,
            ProxyEntity.TYPE_HYSTERIA,
            ProxyEntity.TYPE_TUIC,
            ProxyEntity.TYPE_SHADOWTLS,
            ProxyEntity.TYPE_ANYTLS,
            ProxyEntity.TYPE_NAIVE,
            ProxyEntity.TYPE_MIERU -> TransportClass.TLS

            ProxyEntity.TYPE_HTTP -> {
                val security = profile.httpBean?.security
                if (security.equals("tls", ignoreCase = true)) {
                    TransportClass.TLS
                } else {
                    TransportClass.PLAIN
                }
            }

            ProxyEntity.TYPE_VMESS -> {
                val security = profile.vmessBean?.security
                if (security.equals("tls", ignoreCase = true)) TransportClass.TLS else TransportClass.PLAIN
            }

            ProxyEntity.TYPE_SOCKS,
            ProxyEntity.TYPE_SS,
            ProxyEntity.TYPE_SSH,
            ProxyEntity.TYPE_WG -> TransportClass.PLAIN

            else -> TransportClass.MIXED
        }
    }
}
