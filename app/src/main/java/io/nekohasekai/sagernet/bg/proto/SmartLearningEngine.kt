package io.nekohasekai.sagernet.bg.proto

import io.nekohasekai.sagernet.database.DataStore

/**
 * Centralized smart-learning state access.
 *
 * This is intentionally a thin facade over the existing persisted state so we can
 * migrate behavior incrementally without changing runtime semantics first.
 */
object SmartLearningEngine {

    private const val EMA_ALPHA_SCALE = 1000
    private const val DEFAULT_QUALITY_ALPHA = 180
    private const val DEFAULT_BANDWIDTH_ALPHA = 220
    private const val DEFAULT_JITTER_ALPHA = 240

    data class Observation(
        val profileId: Long,
        val groupId: Long,
        val scope: String,
        val transportClass: String,
        val score: Int?,
        val successRatio: Double,
        val jitter: Int,
        val worst: Int,
        val bandwidthKbps: Int,
    )

    data class HealthSummary(
        val qualityScore: Int,
        val confidence: Int,
        val failureStreak: Int,
        val successCount: Int,
        val failureCount: Int,
        val healthPenalty: Int,
        val quarantineUntil: Long,
        val lastScore: Int,
        val lastBandwidthKbps: Int,
        val lastObservedAt: Long,
    )

    fun getSummary(profileId: Long): HealthSummary {
        return HealthSummary(
            qualityScore = DataStore.getSmartQualityScore(profileId),
            confidence = confidenceScore(profileId),
            failureStreak = DataStore.getSmartFailureStreak(profileId),
            successCount = DataStore.getSmartSuccessCount(profileId),
            failureCount = DataStore.getSmartFailureCount(profileId),
            healthPenalty = DataStore.getSmartHealthPenalty(profileId),
            quarantineUntil = DataStore.getSmartQuarantineUntil(profileId),
            lastScore = DataStore.getSmartLastScore(profileId),
            lastBandwidthKbps = DataStore.getSmartLastBandwidthKbps(profileId),
            lastObservedAt = DataStore.getSmartLastObservedAt(profileId),
        )
    }

    fun isQuarantined(profileId: Long, now: Long = System.currentTimeMillis()): Boolean {
        return DataStore.isSmartQuarantined(profileId, now)
    }

    fun observe(result: Observation) {
        val oldPenalty = DataStore.getSmartHealthPenalty(result.profileId)
        val oldStreak = DataStore.getSmartFailureStreak(result.profileId)
        val scopeHash = normalizedScopeKey(result.scope)
        val transportHash = normalizedTransportKey(result.transportClass)

        if (result.score == null) {
            DataStore.setSmartFailureCount(
                result.profileId,
                DataStore.getSmartFailureCount(result.profileId) + 1
            )
            DataStore.setSmartLastFailureAt(result.profileId, System.currentTimeMillis())
            DataStore.setSmartLastScore(result.profileId, -1)
            DataStore.setSmartLastBandwidthKbps(result.profileId, -1)
            DataStore.bumpSmartRecentSwitchCount(result.profileId)
            observeEma(result.profileId, "score", -1, DEFAULT_QUALITY_ALPHA)
            observeEma(result.profileId, "bandwidth", -1, DEFAULT_BANDWIDTH_ALPHA)
            observeEma(result.profileId, "jitter", result.jitter, DEFAULT_JITTER_ALPHA)
            observeEma(result.profileId, "scope.$scopeHash.fail", 1, DEFAULT_QUALITY_ALPHA)
            observeEma(result.profileId, "transport.$transportHash.fail", 1, DEFAULT_QUALITY_ALPHA)

            val newStreak = (oldStreak + 1).coerceAtMost(20)
            val bump = (220 + newStreak * 30).coerceAtMost(700)
            DataStore.setSmartFailureStreak(result.profileId, newStreak)
            DataStore.setSmartHealthPenalty(result.profileId, oldPenalty + bump)

            when {
                newStreak >= 6 -> DataStore.quarantineSmartProfile(
                    result.profileId,
                    DataStore.smartQuarantineLongMin
                )
                newStreak >= 4 -> DataStore.quarantineSmartProfile(
                    result.profileId,
                    DataStore.smartQuarantineMediumMin
                )
                newStreak >= 2 -> DataStore.quarantineSmartProfile(
                    result.profileId,
                    DataStore.smartQuarantineShortMin
                )
            }
            return
        }

        DataStore.setSmartSuccessCount(
            result.profileId,
            DataStore.getSmartSuccessCount(result.profileId) + 1
        )
        DataStore.setSmartLastSuccessAt(result.profileId, System.currentTimeMillis())
        DataStore.setSmartLastScore(result.profileId, result.score)
        DataStore.setSmartLastBandwidthKbps(result.profileId, result.bandwidthKbps)
        observeEma(result.profileId, "score", result.score, DEFAULT_QUALITY_ALPHA)
        observeEma(result.profileId, "bandwidth", result.bandwidthKbps, DEFAULT_BANDWIDTH_ALPHA)
        observeEma(result.profileId, "jitter", result.jitter, DEFAULT_JITTER_ALPHA)
        observeEma(result.profileId, "scope.$scopeHash.fail", 0, DEFAULT_QUALITY_ALPHA)
        observeEma(result.profileId, "transport.$transportHash.fail", 0, DEFAULT_QUALITY_ALPHA)

        val stable = result.successRatio >= 0.80 && result.jitter <= 120
        val newStreak = (oldStreak - 2).coerceAtLeast(0)
        val baseDrop = if (stable) 220 else 120
        val softness = if (result.successRatio < 0.65) 60 else 0

        DataStore.setSmartFailureStreak(result.profileId, newStreak)
        DataStore.setSmartHealthPenalty(result.profileId, oldPenalty - baseDrop + softness)
        DataStore.decaySmartRecentSwitchCount(result.profileId, if (stable) 2 else 1)
        if (stable || newStreak == 0) {
            DataStore.clearSmartQuarantine(result.profileId)
        }
    }

    fun qualityScore(profileId: Long): Int = DataStore.getSmartQualityScore(profileId)

    fun healthPenalty(profileId: Long): Int = DataStore.getSmartHealthPenalty(profileId)

    fun lastScore(profileId: Long): Int = DataStore.getSmartLastScore(profileId)

    fun lastBandwidthKbps(profileId: Long): Int = DataStore.getSmartLastBandwidthKbps(profileId)

    fun recentSwitchCount(profileId: Long): Int = DataStore.getSmartRecentSwitchCount(profileId)

    fun failureStreak(profileId: Long): Int = DataStore.getSmartFailureStreak(profileId)

    fun successCount(profileId: Long): Int = DataStore.getSmartSuccessCount(profileId)

    fun failureCount(profileId: Long): Int = DataStore.getSmartFailureCount(profileId)

    fun lastObservedAt(profileId: Long): Long = DataStore.getSmartLastObservedAt(profileId)

    fun confidenceScore(profileId: Long): Int {
        val success = DataStore.getSmartSuccessCount(profileId)
        val failure = DataStore.getSmartFailureCount(profileId)
        val lastObservedAt = DataStore.getSmartLastObservedAt(profileId)
        val attempts = success + failure
        val attemptScore = when {
            attempts >= 20 -> 40
            attempts >= 12 -> 30
            attempts >= 6 -> 20
            attempts >= 3 -> 12
            attempts >= 1 -> 6
            else -> 0
        }
        val recencyScore = when {
            lastObservedAt <= 0L -> 0
            System.currentTimeMillis() - lastObservedAt <= 5 * 60_000L -> 20
            System.currentTimeMillis() - lastObservedAt <= 30 * 60_000L -> 12
            else -> 4
        }
        val reliabilityScore = if (attempts > 0) {
            ((success.toDouble() / attempts.toDouble()) * 40.0).toInt()
        } else {
            12
        }
        return (attemptScore + recencyScore + reliabilityScore).coerceIn(0, 100)
    }

    fun formatSummary(profileId: Long): String {
        val summary = getSummary(profileId)
        val quarantine = if (summary.quarantineUntil > System.currentTimeMillis()) {
            "quarantine"
        } else {
            "active"
        }
        return "quality=${summary.qualityScore}/100 confidence=${summary.confidence}/100 streak=${summary.failureStreak} status=$quarantine"
    }

    fun preferredProxy(groupId: Long): Long = DataStore.getSmartPreferredProxy(groupId)

    fun preferredOrder(groupId: Long): List<Long> = DataStore.getSmartPreferredOrder(groupId)

    fun setPreferredProxy(groupId: Long, profileId: Long) {
        DataStore.setSmartPreferredProxy(groupId, profileId)
    }

    fun setPreferredOrder(groupId: Long, orderedIds: List<Long>) {
        DataStore.setSmartPreferredOrder(groupId, orderedIds)
    }

    fun getEma(profileId: Long, metric: String): Int {
        return DataStore.configurationStore.getInt("smartEma.$profileId.$metric", -1)
    }

    private fun observeEma(profileId: Long, metric: String, sample: Int, alpha: Int) {
        val key = "smartEma.$profileId.$metric"
        val current = DataStore.configurationStore.getInt(key, -1)
        val next = if (current < 0) {
            sample
        } else {
            val safeAlpha = alpha.coerceIn(50, 600)
            ((current * (EMA_ALPHA_SCALE - safeAlpha)) + (sample * safeAlpha)) / EMA_ALPHA_SCALE
        }
        DataStore.configurationStore.putInt(key, next.coerceIn(-1, 1_000_000))
    }

    private fun normalizedScopeKey(scope: String): String {
        val normalized = scope.trim().ifBlank { "default" }
        return normalized.hashCode().toUInt().toString(16)
    }

    private fun normalizedTransportKey(raw: String): String {
        return when (raw.lowercase()) {
            "tls" -> "tls"
            "plain" -> "plain"
            else -> "mixed"
        }
    }
}
