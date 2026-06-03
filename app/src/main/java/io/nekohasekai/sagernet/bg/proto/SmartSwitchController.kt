package io.nekohasekai.sagernet.bg.proto

import io.nekohasekai.sagernet.bg.BaseService
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import kotlinx.coroutines.delay
import libcore.Libcore
import kotlin.math.max

class SmartSwitchController(
    private val service: BaseService.Interface,
    private val data: BaseService.Data,
    private val profile: ProxyEntity,
) {
    fun start() {
        data.smartSwitchJob?.cancel()
        data.smartSwitchJob = runOnDefaultDispatcher {
            val cooldownMs = DataStore.smartSwitchCooldownSec.coerceIn(30, 900) * 1000L
            val minDwellMs = DataStore.smartSwitchMinDwellSec.coerceIn(30, 1200) * 1000L
            val normalProbeMs = DataStore.smartSwitchProbeIntervalSec.coerceIn(10, 120) * 1000L
            val badProbeMs = DataStore.smartSwitchBadProbeIntervalSec.coerceIn(5, 60) * 1000L
            val warmupRounds = DataStore.smartSwitchWarmupRounds.coerceIn(1, 8)
            val baseWins = DataStore.smartSwitchCandidateWins.coerceIn(2, 10)
            val warmupWins = DataStore.smartSwitchCandidateWinsWarmup.coerceIn(1, 5)
            val minImproveAbs = DataStore.smartSwitchMinImproveAbs.coerceIn(80, 1200)
            val minImprovePct = DataStore.smartSwitchMinImprovePct.coerceIn(8, 60)
            val weakScore = DataStore.smartSwitchWeakScore.coerceIn(600, 3000)
            val criticalScore = DataStore.smartSwitchCriticalScore.coerceIn(800, 5000)
            val failTrigger = DataStore.smartSwitchFailStreakTrigger.coerceIn(1, 10)
            val stableLockMs = DataStore.smartSwitchStableLockSec.coerceIn(120, 3600) * 1000L
            val excellentScore = DataStore.smartSwitchExcellentScore.coerceIn(450, 1400)
            val minThroughputGainPct = DataStore.smartSwitchMinThroughputGainPct.coerceIn(5, 80)
            val disruptionHoldMinMs = DataStore.smartDisruptionHoldMinSec.coerceIn(30, 900) * 1000L
            val disruptionHoldMaxMs = DataStore.smartDisruptionHoldMaxSec.coerceIn(60, 1800) * 1000L
            var activeId = 0L
            var activeSinceMs = System.currentTimeMillis()
            var lastSwitchAtMs = 0L
            var pendingCandidateId = 0L
            var pendingWins = 0
            var nullProbeStreak = 0
            var stableRounds = 0
            var criticalRounds = 0
            var lastRescueAtMs = 0L
            var standbyId = 0L
            var disruptionNullStreak = 0
            var disruptionRecoveryWins = 0
            var disruptionUntilMs = 0L
            var lastAutoTuneAtMs = 0L
            var trafficStallRounds = 0
            var lastTrafficRescueAtMs = 0L
            val learningEnabled = DataStore.smartEnableNetworkLearning

            fun activeStats(): Pair<Int, Int> {
                if (activeId <= 0L) return Pair(-1, 0)
                return Pair(DataStore.getSmartLastScore(activeId), DataStore.getSmartFailureStreak(activeId))
            }

            fun bandwidth(profileId: Long): Int {
                if (profileId <= 0L) return -1
                return DataStore.getSmartLastBandwidthKbps(profileId)
            }

            fun currentScope(): String {
                if (!learningEnabled) return "default"
                return service.smartSwitchScope()
            }

            fun setDecision(reason: String) {
                if (!DataStore.smartDebugEnabled) return
                DataStore.smartLastDecision = reason
            }

            fun updateSessionHealth(score: Int, streak: Int, bw: Int) {
                val latencyPart = when {
                    score <= 0 -> 0
                    score <= 180 -> 45
                    score <= 350 -> 35
                    score <= 700 -> 25
                    score <= 1200 -> 14
                    else -> 6
                }
                val throughputPart = when {
                    bw >= 24_000 -> 35
                    bw >= 16_000 -> 30
                    bw >= 10_000 -> 24
                    bw >= 6_000 -> 18
                    bw >= 3_000 -> 12
                    bw > 0 -> 6
                    else -> 0
                }
                val streakPenalty = (streak.coerceAtLeast(0) * 6).coerceAtMost(40)
                DataStore.smartSessionHealth = (latencyPart + throughputPart - streakPenalty).coerceIn(0, 100)
            }

            fun isCritical(score: Int, streak: Int): Boolean {
                return score <= 0 || score >= criticalScore || streak >= failTrigger + 1
            }

            fun isWeak(score: Int, streak: Int): Boolean {
                return isCritical(score, streak) || score >= weakScore || streak >= failTrigger
            }

            fun selectOutboundById(id: Long): Boolean {
                if (id <= 0L) return false
                val tag = data.proxy?.config?.profileTagMap?.get(id).orEmpty()
                if (tag.isBlank()) return false
                data.proxy?.box?.selectOutbound(tag)
                activeId = id
                activeSinceMs = System.currentTimeMillis()
                lastSwitchAtMs = activeSinceMs
                DataStore.setSmartPreferredProxy(profile.groupId, id)
                DataStore.setSmartPreferredProxyScoped(currentScope(), profile.groupId, id)
                setDecision("switch:$id")
                return true
            }

            fun maybeSwitchTo(id: Long, warmup: Boolean) {
                if (id <= 0L) return
                if (id == activeId) {
                    pendingCandidateId = 0L
                    pendingWins = 0
                    return
                }
                val candidateScore = DataStore.getSmartLastScore(id)
                if (candidateScore <= 0) return
                val now = System.currentTimeMillis()
                val (activeScore, activeStreak) = activeStats()
                val trafficEmergency = trafficStallRounds >= 2
                val activeCritical = isCritical(activeScore, activeStreak) || trafficEmergency
                val activeWeak = isWeak(activeScore, activeStreak) || trafficStallRounds >= 1
                val activeGood = activeScore in 1..excellentScore && activeStreak == 0
                val activeBw = bandwidth(activeId)
                val candidateBw = bandwidth(id)
                if (!warmup && !activeCritical && now < disruptionUntilMs) {
                    setDecision("hold:disruption_window")
                    return
                }
                if (!warmup && !activeCritical && now - lastSwitchAtMs < cooldownMs) return
                if (!activeCritical && now - activeSinceMs < minDwellMs) return
                if (!warmup && activeGood && now - activeSinceMs < stableLockMs) {
                    setDecision("hold:stable_lock")
                    return
                }
                val improveAbs = if (activeScore > 0) activeScore - candidateScore else Int.MAX_VALUE
                val improvePctEnough =
                    activeScore <= 0 || candidateScore * 100 <= activeScore * (100 - minImprovePct)
                val improveAbsEnough = activeScore <= 0 || improveAbs >= minImproveAbs
                val throughputGainEnough = if (activeBw > 0 && candidateBw > 0) {
                    candidateBw * 100 >= activeBw * (100 + minThroughputGainPct)
                } else {
                    false
                }
                val activeExcellent = activeGood
                val improveEnough = when {
                    activeCritical -> true
                    activeExcellent -> {
                        val strictAbs = minImproveAbs + 180
                        val strictPct = (minImprovePct + 8).coerceAtMost(70)
                        improveAbs >= strictAbs ||
                            candidateScore * 100 <= activeScore * (100 - strictPct) ||
                            throughputGainEnough
                    }
                    else -> improveAbsEnough || improvePctEnough || throughputGainEnough
                }
                if (!improveEnough) {
                    if (pendingCandidateId == id) pendingWins = 0
                    setDecision("hold:no_significant_gain")
                    return
                }
                if (pendingCandidateId == id) {
                    pendingWins++
                } else {
                    pendingCandidateId = id
                    pendingWins = 1
                }
                val requiredWins = when {
                    activeCritical -> 1
                    warmup -> warmupWins + if (activeExcellent) 1 else 0
                    activeWeak -> baseWins
                    else -> baseWins + 1
                }.coerceAtLeast(1)
                if (pendingWins < requiredWins) return
                if (selectOutboundById(id)) {
                    pendingCandidateId = 0L
                    pendingWins = 0
                }
            }

            val scopedPreferredId = DataStore.getSmartPreferredProxyScoped(currentScope(), profile.groupId)
            val preferredId = DataStore.getSmartPreferredProxy(profile.groupId)
            if (scopedPreferredId > 0L) {
                selectOutboundById(scopedPreferredId)
            } else if (preferredId > 0L) {
                selectOutboundById(preferredId)
            }
            val fastTop = SmartSelector.selectTopFast(profile.groupId, 3, currentScope())
            val fastId = fastTop.firstOrNull()
            standbyId = fastTop.getOrNull(1) ?: 0L
            if (fastId != null) {
                maybeSwitchTo(fastId, warmup = true)
            }
            SmartSelector.applyCachedOrder(profile.groupId)
            val best = SmartSelector.selectBest(profile.groupId, currentScope())
            if (best != null) {
                maybeSwitchTo(best, warmup = true)
            }
            repeat(warmupRounds) {
                delay(badProbeMs)
                if (DataStore.serviceState != BaseService.State.Connected) return@runOnDefaultDispatcher
                val id = SmartSelector.selectBestFast(profile.groupId, currentScope()) ?: return@repeat
                maybeSwitchTo(id, warmup = true)
            }
            while (DataStore.serviceState == BaseService.State.Connected) {
                val now = System.currentTimeMillis()
                val (score, streak) = activeStats()
                val txRate = DataStore.smartMainTxRate
                val rxRate = DataStore.smartMainRxRate
                val requestWithoutResponse = txRate >= 900L && rxRate <= 800L
                val poorInteractiveDownload = txRate >= 500L && rxRate in 1L..48_000L
                val poorStreamingDownload = rxRate in 1L..32_000L && score >= weakScore
                val trafficDegraded = requestWithoutResponse || poorInteractiveDownload || poorStreamingDownload
                trafficStallRounds = if (trafficDegraded) {
                    (trafficStallRounds + 1).coerceAtMost(20)
                } else {
                    0
                }
                val stallCritical = trafficStallRounds >= 2 && (requestWithoutResponse || score >= weakScore)
                val degradedCritical = trafficStallRounds >= 3
                val trafficCritical = stallCritical || degradedCritical
                val weak = isWeak(score, streak) || trafficStallRounds >= 1
                val critical = isCritical(score, streak) || trafficCritical
                updateSessionHealth(score, streak, bandwidth(activeId))
                if (trafficCritical) {
                    DataStore.smartSessionHealth = DataStore.smartSessionHealth.coerceAtMost(25)
                    setDecision("critical:traffic_degraded tx=$txRate rx=$rxRate score=$score")
                }
                if (now - lastAutoTuneAtMs >= 180_000L) {
                    lastAutoTuneAtMs = now
                    val health = DataStore.smartSessionHealth
                    if (health < 35 && DataStore.connectionTestConcurrent < 32) {
                        DataStore.connectionTestConcurrent = (DataStore.connectionTestConcurrent + 2).coerceAtMost(32)
                        setDecision("tune:raise_probe_concurrency")
                    } else if (health > 85 && DataStore.connectionTestConcurrent > 14) {
                        DataStore.connectionTestConcurrent = (DataStore.connectionTestConcurrent - 1).coerceAtLeast(14)
                        setDecision("tune:lower_probe_concurrency")
                    }
                }
                if (!weak && score in 1..excellentScore && streak == 0) {
                    stableRounds = (stableRounds + 1).coerceAtMost(120)
                } else {
                    stableRounds = 0
                }
                criticalRounds = if (critical) (criticalRounds + 1).coerceAtMost(60) else 0
                val stabilityMultiplier = when {
                    stableRounds >= 24 -> 4L
                    stableRounds >= 12 -> 3L
                    stableRounds >= 6 -> 2L
                    else -> 1L
                }
                val delayMs = if (weak) badProbeMs else normalProbeMs * stabilityMultiplier
                delay(delayMs)
                if (trafficCritical) {
                    val stallNow = System.currentTimeMillis()
                    if (stallNow - lastTrafficRescueAtMs >= 20_000L) {
                        lastTrafficRescueAtMs = stallNow
                        runCatching { Libcore.resetAllConnections(true) }
                    }
                    val stallRescueId = SmartSelector.selectBestFast(profile.groupId, currentScope())
                        ?: SmartSelector.selectBest(profile.groupId, currentScope())
                    if (stallRescueId != null) {
                        maybeSwitchTo(stallRescueId, warmup = false)
                    }
                }
                if (criticalRounds >= 4 && now >= disruptionUntilMs) {
                    if (standbyId > 0L) {
                        maybeSwitchTo(standbyId, warmup = false)
                    }
                    val now2 = System.currentTimeMillis()
                    if (now2 - lastRescueAtMs >= 120_000L) {
                        lastRescueAtMs = now2
                        runCatching { Libcore.resetAllConnections(true) }
                        val rescueId = SmartSelector.selectBest(profile.groupId, currentScope())
                        if (rescueId != null) {
                            maybeSwitchTo(rescueId, warmup = false)
                            continue
                        }
                    }
                }
                val top = SmartSelector.selectTopFast(profile.groupId, 3, currentScope())
                val id = top.firstOrNull()
                standbyId = top.getOrNull(1) ?: standbyId
                if (id == null) {
                    nullProbeStreak++
                    disruptionNullStreak++
                    disruptionRecoveryWins = 0
                    setDecision("hold:global_disruption_probe_null")
                    if (disruptionNullStreak >= 2) {
                        val holdMs = (badProbeMs * 6).coerceIn(disruptionHoldMinMs, disruptionHoldMaxMs)
                        disruptionUntilMs = maxOf(disruptionUntilMs, System.currentTimeMillis() + holdMs)
                    }
                    if (nullProbeStreak >= 3) {
                        nullProbeStreak = 0
                        if (critical) {
                            val deepId = SmartSelector.selectBest(profile.groupId, currentScope()) ?: continue
                            maybeSwitchTo(deepId, warmup = false)
                        } else {
                            setDecision("hold:global_disruption_no_deep_switch")
                        }
                    }
                    continue
                }
                nullProbeStreak = 0
                if (System.currentTimeMillis() < disruptionUntilMs && !critical) {
                    disruptionRecoveryWins++
                    setDecision("hold:global_disruption")
                    if (disruptionRecoveryWins >= 3) {
                        disruptionNullStreak = 0
                        disruptionRecoveryWins = 0
                        disruptionUntilMs = 0L
                        setDecision("recover:global_disruption_cleared")
                    }
                    continue
                }
                disruptionNullStreak = 0
                disruptionRecoveryWins = 0
                maybeSwitchTo(id, warmup = false)
            }
        }
    }
}
