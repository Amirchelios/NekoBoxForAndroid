package io.nekohasekai.sagernet.bg.proto

import io.nekohasekai.sagernet.database.DataStore
import java.net.HttpURLConnection
import java.net.URL

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
        val failureReason: String,
    )

    data class HealthSummary(
        val qualityScore: Int,
        val confidence: Int,
        val scopeConfidence: Int,
        val transportConfidence: Int,
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
            scopeConfidence = scopeConfidence(profileId),
            transportConfidence = transportConfidence(profileId),
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
        val oldLastScore = DataStore.getSmartLastScore(result.profileId)
        val scopeHash = normalizedScopeKey(result.scope)
        val transportHash = normalizedTransportKey(result.transportClass)

        if (result.score == null) {
            val networkWideFailure = result.failureReason == FAILURE_AMBIENT_NETWORK ||
                result.failureReason == FAILURE_CORE_UNREADY
            DataStore.setSmartFailureCount(
                result.profileId,
                DataStore.getSmartFailureCount(result.profileId) + 1
            )
            DataStore.setSmartLastFailureAt(result.profileId, System.currentTimeMillis())
            DataStore.setSmartLastFailureReason(result.profileId, result.failureReason)
            DataStore.setSmartLastScore(result.profileId, -1)
            DataStore.setSmartLastBandwidthKbps(result.profileId, -1)
            if (!networkWideFailure) {
                DataStore.bumpSmartRecentSwitchCount(result.profileId)
            }
            observeEma(result.profileId, "score", -1, DEFAULT_QUALITY_ALPHA)
            observeEma(result.profileId, "bandwidth", -1, DEFAULT_BANDWIDTH_ALPHA)
            observeEma(result.profileId, "jitter", result.jitter, DEFAULT_JITTER_ALPHA)
            observeEma(result.profileId, "scope.$scopeHash.fail", 1, DEFAULT_QUALITY_ALPHA)
            observeEma(result.profileId, "transport.$transportHash.fail", 1, DEFAULT_QUALITY_ALPHA)

            val newStreak = if (networkWideFailure) {
                oldStreak.coerceAtMost(2)
            } else {
                (oldStreak + 1).coerceAtMost(20)
            }
            val bumpBase = if (networkWideFailure) 70 else 220
            val bump = (bumpBase + newStreak * 30).coerceAtMost(if (networkWideFailure) 260 else 700)
            DataStore.setSmartFailureStreak(result.profileId, newStreak)
            DataStore.setSmartHealthPenalty(result.profileId, oldPenalty + bump)

            if (!networkWideFailure) {
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
            }
            return
        }

        DataStore.setSmartSuccessCount(
            result.profileId,
            DataStore.getSmartSuccessCount(result.profileId) + 1
        )
        DataStore.setSmartLastSuccessAt(result.profileId, System.currentTimeMillis())
        DataStore.setSmartLastFailureReason(result.profileId, "")
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
        val suddenDropPenalty = if (oldLastScore > 0 && oldLastScore - result.score > 300) {
            ((oldLastScore - result.score) / 2).coerceAtMost(420)
        } else {
            0
        }

        DataStore.setSmartFailureStreak(result.profileId, newStreak)
        DataStore.setSmartHealthPenalty(result.profileId, oldPenalty - baseDrop + softness + suddenDropPenalty)
        DataStore.decaySmartRecentSwitchCount(result.profileId, if (stable) 2 else 1)
        if (stable || newStreak == 0) {
            DataStore.clearSmartQuarantine(result.profileId)
        } else if (suddenDropPenalty >= 200) {
            DataStore.quarantineSmartProfile(result.profileId, DataStore.smartQuarantineMediumMin)
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

    fun scopeConfidence(profileId: Long, scope: String = "default"): Int {
        return emaConfidence(profileId, "scope.${normalizedScopeKey(scope)}.fail")
    }

    fun transportConfidence(profileId: Long, transportClass: String = "mixed"): Int {
        return emaConfidence(profileId, "transport.${normalizedTransportKey(transportClass)}.fail")
    }

    fun compositeScore(profileId: Long, scope: String = "default", transportClass: String = "mixed"): Int {
        val quality = qualityScore(profileId)
        val confidence = confidenceScore(profileId)
        val scopeConfidence = scopeConfidence(profileId, scope)
        val transportConfidence = transportConfidence(profileId, transportClass)
        val recency = when {
            lastObservedAt(profileId) <= 0L -> 0
            System.currentTimeMillis() - lastObservedAt(profileId) <= 10 * 60_000L -> 8
            System.currentTimeMillis() - lastObservedAt(profileId) <= 30 * 60_000L -> 4
            else -> 0
        }
        val streakPenalty = (failureStreak(profileId) * 6).coerceAtMost(60)
        val churnPenalty = (recentSwitchCount(profileId) * 4).coerceAtMost(40)
        return (quality * 4 + confidence * 3 + scopeConfidence * 3 + transportConfidence * 3 + recency -
            streakPenalty - churnPenalty)
            .coerceIn(0, 1000)
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

    fun probeAmbientNetwork(): Boolean {
        val urls = listOf(
            "https://cp.cloudflare.com/generate_204",
            "https://www.gstatic.com/generate_204"
        )
        for (raw in urls) {
            val ok = runCatching {
                val connection = URL(raw).openConnection() as HttpURLConnection
                connection.connectTimeout = 1500
                connection.readTimeout = 1500
                connection.instanceFollowRedirects = false
                connection.requestMethod = "GET"
                val code = connection.responseCode
                connection.disconnect()
                code in 200..204
            }.getOrDefault(false)
            if (ok) return true
        }
        return false
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

    private fun emaConfidence(profileId: Long, metric: String): Int {
        val ema = getEma(profileId, metric)
        if (ema < 0) return 0
        return when {
            ema <= 0 -> 0
            ema >= 80 -> 100
            ema >= 50 -> 80
            ema >= 20 -> 55
            else -> 30
        }
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

    const val FAILURE_NONE = "none"
    const val FAILURE_AMBIENT_NETWORK = "ambient_network"
    const val FAILURE_CORE_UNREADY = "core_unready"
    const val FAILURE_LOW_SUCCESS = "proxy_low_success"
    const val FAILURE_HIGH_JITTER = "proxy_high_jitter"
    const val FAILURE_HIGH_WORST = "proxy_high_worst"
}
