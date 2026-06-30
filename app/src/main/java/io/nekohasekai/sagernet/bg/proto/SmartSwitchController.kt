package io.nekohasekai.sagernet.bg.proto

import io.nekohasekai.sagernet.bg.BaseService
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import io.nekohasekai.sagernet.bg.proto.SmartLearningEngine
import kotlinx.coroutines.delay
import libcore.Libcore

class SmartSwitchController(
    private val service: BaseService.Interface,
    private val data: BaseService.Data,
    private val profile: ProxyEntity,
) {
    fun start() {
        data.smartSwitchJob?.cancel()
        data.smartSwitchJob = runOnDefaultDispatcher {
            val mode = DataStore.normalizedSmartProfilePreset()
            val policy = DataStore.smartAdaptivePolicy()
            val sensitivity = DataStore.smartSwitchSensitivity
            DataStore.smartRuntimeGroupId = profile.groupId
            DataStore.smartStandbyProxyId = 0L
            if (mode == "manual") {
                DataStore.smartLastDecision = "manual:auto_switch_disabled"
                return@runOnDefaultDispatcher
            }
            val cooldownFactor = when (mode) {
                "gaming" -> 0.65
                "streaming" -> 1.15
                "download" -> 1.35
                else -> 1.0
            }
            val dwellFactor = when (mode) {
                "gaming" -> 0.70
                "streaming" -> 1.20
                "download" -> 1.40
                else -> 1.0
            }
            val cooldownMs = (policy.cooldownSec.coerceIn(20, 900) * cooldownFactor).toLong() * 1000L
            val minDwellMs = (policy.minDwellSec.coerceIn(20, 1200) * dwellFactor).toLong() * 1000L
            val normalProbeMs = policy.probeIntervalSec.coerceIn(8, 120) * 1000L
            val badProbeMs = policy.badProbeIntervalSec.coerceIn(3, 60) * 1000L
            val warmupRounds = policy.warmupRounds.coerceIn(1, 8)
            val sensitivityWins = when (sensitivity) {
                "responsive" -> -1
                "conservative" -> 2
                else -> 0
            }
            val sensitivityThresholdPct = when (sensitivity) {
                "responsive" -> 75
                "conservative" -> 135
                else -> 100
            }
            val baseWins = (policy.candidateWins + sensitivityWins).coerceIn(1, 10)
            val warmupWins = (policy.candidateWinsWarmup + sensitivityWins).coerceIn(1, 5)
            val minImproveAbs = (policy.minImproveAbs * sensitivityThresholdPct / 100).coerceIn(80, 1200)
            val minImprovePct = (policy.minImprovePct * sensitivityThresholdPct / 100).coerceIn(8, 60)
            val weakScoreBase = policy.weakScore.coerceIn(600, 3000)
            val criticalScoreBase = policy.criticalScore.coerceIn(800, 5000)
            val weakScore = when (mode) {
                "gaming" -> (weakScoreBase * 0.78).toInt()
                "streaming" -> (weakScoreBase * 1.10).toInt()
                "download" -> (weakScoreBase * 1.20).toInt()
                else -> weakScoreBase
            }.coerceIn(450, 3500)
            val criticalScore = when (mode) {
                "gaming" -> (criticalScoreBase * 0.82).toInt()
                "streaming" -> (criticalScoreBase * 1.10).toInt()
                "download" -> (criticalScoreBase * 1.20).toInt()
                else -> criticalScoreBase
            }.coerceIn(700, 6000)
            val failTrigger = policy.failStreakTrigger.coerceIn(1, 10)
            val stableLockMs = policy.stableLockSec.coerceIn(120, 3600) * 1000L
            val excellentScore = policy.excellentScore.coerceIn(450, 1400)
            val minThroughputGainPct = policy.minThroughputGainPct.coerceIn(5, 80)
            val disruptionHoldMinMs = policy.disruptionHoldMinSec.coerceIn(30, 900) * 1000L
            val disruptionHoldMaxMs = policy.disruptionHoldMaxSec.coerceIn(60, 1800) * 1000L
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

            fun syncActiveFromCore() {
                val coreActiveId = DataStore.smartActiveProxyId
                if (coreActiveId <= 0L || coreActiveId == activeId) return
                activeId = coreActiveId
                activeSinceMs = System.currentTimeMillis()
                if (standbyId == activeId) {
                    standbyId = 0L
                    DataStore.smartStandbyProxyId = 0L
                }
            }

            fun setDecision(reason: String) {
                DataStore.smartLastDecision = reason
            }

            fun setStandby(id: Long) {
                standbyId = id.takeIf { it > 0L && it != activeId } ?: 0L
                DataStore.smartStandbyProxyId = standbyId
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

            fun congestionLevel(score: Int, streak: Int, txRate: Long, rxRate: Long, bw: Int): Int {
                val latencyPressure = when {
                    score <= 0 -> 100
                    score <= 180 -> 12
                    score <= 350 -> 24
                    score <= 700 -> 42
                    score <= 1200 -> 68
                    else -> 85
                }
                val throughputPressure = when {
                    bw >= 24_000 -> 0
                    bw >= 16_000 -> 10
                    bw >= 10_000 -> 20
                    bw >= 6_000 -> 35
                    bw >= 3_000 -> 50
                    bw > 0 -> 65
                    else -> 85
                }
                val flowPressure = when {
                    txRate >= 1_500L && rxRate <= 1_000L -> 45
                    txRate >= 900L && rxRate <= 700L -> 30
                    rxRate in 1L..1_500L && txRate >= 500L -> 18
                    else -> 0
                }
                val streakPressure = (streak.coerceAtLeast(0) * 8).coerceAtMost(40)
                return (latencyPressure + throughputPressure + flowPressure + streakPressure)
                    .coerceIn(0, 100)
            }

            fun applyAdaptiveProbePolicy(pressure: Int, health: Int) {
                val now = System.currentTimeMillis()
                if (now - lastAutoTuneAtMs < 120_000L) return
                lastAutoTuneAtMs = now
                when {
                    pressure >= 75 || health < 35 -> {
                        if (DataStore.connectionTestConcurrent < 40) {
                            DataStore.connectionTestConcurrent =
                                (DataStore.connectionTestConcurrent + 4).coerceAtMost(40)
                            setDecision("tune:boost_probe_concurrency")
                        }
                        if (DataStore.parallelConcurrency < 34) {
                            DataStore.parallelConcurrency =
                                (DataStore.parallelConcurrency + 2).coerceAtMost(34)
                        }
                        if (DataStore.parallelDelayMs > 80) {
                            DataStore.parallelDelayMs = (DataStore.parallelDelayMs - 15).coerceAtLeast(80)
                        }
                        if (DataStore.parallelTimeoutMs < 9000) {
                            DataStore.parallelTimeoutMs = (DataStore.parallelTimeoutMs + 1000).coerceAtMost(9000)
                        }
                    }
                    pressure >= 50 || health < 65 -> {
                        if (DataStore.connectionTestConcurrent < 34) {
                            DataStore.connectionTestConcurrent =
                                (DataStore.connectionTestConcurrent + 2).coerceAtMost(34)
                            setDecision("tune:raise_probe_concurrency")
                        }
                        if (DataStore.parallelTimeoutMs < 8500) {
                            DataStore.parallelTimeoutMs = (DataStore.parallelTimeoutMs + 500).coerceAtMost(8500)
                        }
                    }
                    health > 90 -> {
                        if (DataStore.connectionTestConcurrent > 18) {
                            DataStore.connectionTestConcurrent =
                                (DataStore.connectionTestConcurrent - 1).coerceAtLeast(18)
                            setDecision("tune:lower_probe_concurrency")
                        }
                    }
                }
            }

            fun isCritical(score: Int, streak: Int): Boolean {
                return score <= 0 || score >= criticalScore || streak >= failTrigger + 1
            }

            fun isWeak(score: Int, streak: Int): Boolean {
                return isCritical(score, streak) || score >= weakScore || streak >= failTrigger
            }

            suspend fun selectOutboundById(id: Long): Boolean {
                if (id <= 0L) return false
                val tag = data.proxy?.config?.profileTagMap?.get(id).orEmpty()
                if (tag.isBlank()) return false
                val previousId = activeId
                val switched = data.proxy?.box?.selectOutbound(tag) == true
                if (!switched) {
                    setDecision("switch_rejected:$id")
                    return false
                }
                activeId = id
                DataStore.smartActiveProxyId = id
                if (standbyId == id) {
                    DataStore.smartStandbyProxyId = 0L
                }
                activeSinceMs = System.currentTimeMillis()
                lastSwitchAtMs = activeSinceMs
                if (previousId > 0L && previousId != id) {
                    DataStore.bumpSmartRecentSwitchCount(previousId)
                }
                SmartLearningEngine.setPreferredProxy(profile.groupId, id)
                DataStore.setSmartPreferredProxyScoped(currentScope(), profile.groupId, id)
                DataStore.bumpSmartRecentSwitchCount(id)
                setDecision("switch:$id")
                if (previousId > 0L && previousId != id && DataStore.smartInterruptExistingConnections) {
                    runCatching { Libcore.resetAllConnections(true) }
                }
                if (previousId > 0L && previousId != id) {
                    val previous = SagerDatabase.proxyDao.getById(previousId)
                    val current = SagerDatabase.proxyDao.getById(id)
                    if (previous != null && current != null) {
                        data.notification?.postServerSwitched(previous, current)
                    }
                }
                return true
            }

            suspend fun maybeSwitchTo(id: Long, warmup: Boolean): Boolean {
                if (id <= 0L) return false
                if (id == activeId) {
                    pendingCandidateId = 0L
                    pendingWins = 0
                    return false
                }
                val candidateScore = DataStore.getSmartLastScore(id)
                if (candidateScore <= 0) return false
                val candidateStreak = DataStore.getSmartFailureStreak(id)
                val candidateQuality = DataStore.getSmartQualityScore(id)
                val now = System.currentTimeMillis()
                val (activeScore, activeStreak) = activeStats()
                val trafficEmergency = trafficStallRounds >= 2
                val activeCritical = isCritical(activeScore, activeStreak) || trafficEmergency
                val activeWeak = isWeak(activeScore, activeStreak) || trafficStallRounds >= 1
                val activeGood = activeScore in 1..excellentScore && activeStreak == 0
                val activeBw = bandwidth(activeId)
                val candidateBw = bandwidth(id)
                val candidateUnstable = candidateStreak >= failTrigger ||
                    (candidateQuality < 35 && candidateScore >= weakScore)
                if (!activeCritical && candidateUnstable) {
                    setDecision("hold:candidate_unstable")
                    return false
                }
                if (activeCritical && candidateStreak > failTrigger && candidateScore >= criticalScore) {
                    setDecision("hold:candidate_critical")
                    return false
                }
                if (!warmup && !activeCritical && now < disruptionUntilMs) {
                    setDecision("hold:disruption_window")
                    return false
                }
                if (!warmup && !activeCritical && now - lastSwitchAtMs < cooldownMs) return false
                if (!activeCritical && now - activeSinceMs < minDwellMs) return false
                if (!warmup && activeGood && now - activeSinceMs < stableLockMs) {
                    setDecision("hold:stable_lock")
                    return false
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
                    return false
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
                }.let {
                    if (candidateQuality >= 70 && candidateStreak == 0) it - 1 else it
                }.coerceAtLeast(1)
                if (pendingWins < requiredWins) return false
                if (selectOutboundById(id)) {
                    pendingCandidateId = 0L
                    pendingWins = 0
                    return true
                }
                return false
            }

            val scopedPreferredId = DataStore.getSmartPreferredProxyScoped(currentScope(), profile.groupId)
            val preferredId = SmartLearningEngine.preferredProxy(profile.groupId)
            if (scopedPreferredId > 0L) {
                selectOutboundById(scopedPreferredId)
            } else if (preferredId > 0L) {
                selectOutboundById(preferredId)
            }
            val fastTop = SmartSelector.selectTopFast(profile.groupId, 3, currentScope())
            val fastId = fastTop.firstOrNull()
            setStandby(fastTop.firstOrNull { it != activeId } ?: 0L)
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
                syncActiveFromCore()
                val now = System.currentTimeMillis()
                val (score, streak) = activeStats()
                val txRate = DataStore.smartMainTxRate
                val rxRate = DataStore.smartMainRxRate
                val requestWithoutResponse = txRate >= 900L && rxRate <= 800L
                val interactiveLimit = when (mode) {
                    "gaming" -> 96_000L
                    "streaming" -> 40_000L
                    "download" -> 24_000L
                    else -> 48_000L
                }
                val streamingLimit = when (mode) {
                    "streaming" -> 96_000L
                    "download" -> 48_000L
                    "gaming" -> 40_000L
                    else -> 64_000L
                }
                val poorInteractiveDownload = txRate >= 500L && rxRate in 1L..interactiveLimit
                val poorStreamingDownload = rxRate in 1L..streamingLimit && score >= weakScore
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
                val activeBw = bandwidth(activeId)
                val pressure = congestionLevel(score, streak, txRate, rxRate, activeBw)
                updateSessionHealth(score, streak, activeBw)
                setDecision(
                    "monitor:active=$activeId standby=$standbyId score=$score " +
                        "health=${DataStore.smartSessionHealth} pressure=$pressure"
                )
                if (trafficCritical) {
                    DataStore.smartSessionHealth = DataStore.smartSessionHealth.coerceAtMost(25)
                    setDecision("critical:traffic_degraded tx=$txRate rx=$rxRate score=$score")
                }
                applyAdaptiveProbePolicy(pressure, DataStore.smartSessionHealth)
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
                val pressureMultiplier = when {
                    pressure >= 80 -> 1L
                    pressure >= 55 -> 2L
                    else -> stabilityMultiplier
                }
                val delayMs = if (weak || pressure >= 55) {
                    badProbeMs.coerceAtMost(normalProbeMs * pressureMultiplier)
                } else {
                    normalProbeMs * pressureMultiplier
                }
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
                if (pressure >= 85) {
                    val rescueId = SmartSelector.selectBestFast(profile.groupId, currentScope())
                        ?: SmartSelector.selectBest(profile.groupId, currentScope())
                    if (rescueId != null) {
                        maybeSwitchTo(rescueId, warmup = false)
                        continue
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
                setStandby(top.firstOrNull { it != activeId } ?: standbyId)
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
