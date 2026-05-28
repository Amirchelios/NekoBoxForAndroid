package io.nekohasekai.sagernet.bg
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.*
import android.widget.Toast
import io.nekohasekai.sagernet.Action
import io.nekohasekai.sagernet.BootReceiver
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.aidl.ISagerNetService
import io.nekohasekai.sagernet.aidl.ISagerNetServiceCallback
import io.nekohasekai.sagernet.bg.proto.ProxyInstance
import io.nekohasekai.sagernet.bg.proto.SmartSelector
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.GroupManager
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.broadcastReceiver
import io.nekohasekai.sagernet.ktx.readableMessage
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import io.nekohasekai.sagernet.ktx.runOnMainDispatcher
import io.nekohasekai.sagernet.plugin.PluginManager
import io.nekohasekai.sagernet.utils.DefaultNetworkListener
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import libcore.Libcore
import moe.matsuri.nb4a.Protocols
import moe.matsuri.nb4a.utils.Util
import java.net.UnknownHostException
class BaseService {
    enum class State(
        val canStop: Boolean = false,
        val started: Boolean = false,
        val connected: Boolean = false,
    ) {
        /**
         * Idle state is only used by UI and will never be returned by BaseService.
         */
        Idle, Connecting(true, true, false), Connected(true, true, true), Stopping, Stopped,
    }
    interface ExpectedException
    class Data internal constructor(private val service: Interface) {
        var state = State.Stopped
        var proxy: ProxyInstance? = null
        var notification: ServiceNotification? = null
        val receiver = broadcastReceiver { ctx, intent ->
            when (intent.action) {
                Intent.ACTION_SHUTDOWN -> service.persistStats()
                Action.RELOAD -> service.reload()
                // Action.SWITCH_WAKE_LOCK -> runOnDefaultDispatcher { service.switchWakeLock() }
                PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        if (SagerNet.power.isDeviceIdleMode) {
                            proxy?.box?.sleep()
                        } else {
                            proxy?.box?.wake()
                            if (DataStore.wakeResetConnections) {
                                Libcore.resetAllConnections(true)
                            }
                        }
                    }
                }
                Action.RESET_UPSTREAM_CONNECTIONS -> runOnDefaultDispatcher {
                    Libcore.resetAllConnections(true)
                    runOnMainDispatcher {
                        Util.collapseStatusBar(ctx)
                        Toast.makeText(ctx, "Reset upstream connections done", Toast.LENGTH_SHORT)
                            .show()
                    }
                }
                else -> service.stopRunner()
            }
        }
        var closeReceiverRegistered = false
        val binder = Binder(this)
        var connectingJob: Job? = null
        var smartSwitchJob: Job? = null
        fun changeState(s: State, msg: String? = null) {
            if (state == s && msg == null) return
            state = s
            DataStore.serviceState = s
            binder.stateChanged(s, msg)
        }
    }
    class Binder(private var data: Data? = null) : ISagerNetService.Stub(), CoroutineScope,
        AutoCloseable {
        private val callbacks = object : RemoteCallbackList<ISagerNetServiceCallback>() {
            override fun onCallbackDied(callback: ISagerNetServiceCallback?, cookie: Any?) {
                super.onCallbackDied(callback, cookie)
            }
        }
        val callbackIdMap = mutableMapOf<ISagerNetServiceCallback, Int>()
        override val coroutineContext = Dispatchers.Main.immediate + Job()
        override fun getState(): Int = (data?.state ?: State.Idle).ordinal
        override fun getProfileName(): String = data?.proxy?.displayProfileName ?: "Idle"
        override fun registerCallback(cb: ISagerNetServiceCallback, id: Int) {
            if (id == SagerConnection.CONNECTION_ID_RESTART_BG) {
                Runtime.getRuntime().exit(0)
                return
            }
            if (!callbackIdMap.contains(cb)) {
                callbacks.register(cb)
            }
            callbackIdMap[cb] = id
        }
        private val broadcastMutex = Mutex()
        suspend fun broadcast(work: (ISagerNetServiceCallback) -> Unit) {
            broadcastMutex.withLock {
                val count = callbacks.beginBroadcast()
                try {
                    repeat(count) {
                        try {
                            work(callbacks.getBroadcastItem(it))
                        } catch (_: RemoteException) {
                        } catch (_: Exception) {
                        }
                    }
                } finally {
                    callbacks.finishBroadcast()
                }
            }
        }
        override fun unregisterCallback(cb: ISagerNetServiceCallback) {
            callbackIdMap.remove(cb)
            callbacks.unregister(cb)
        }
        override fun urlTest(): Int {
            if (data?.proxy?.box == null) {
                error("core not started")
            }
            try {
                return Libcore.urlTest(
                    data!!.proxy!!.box, DataStore.connectionTestURL, 3000
                )
            } catch (e: Exception) {
                error(Protocols.genFriendlyMsg(e.readableMessage))
            }
        }
        fun stateChanged(s: State, msg: String?) = launch {
            val profileName = profileName
            broadcast { it.stateChanged(s.ordinal, profileName, msg) }
        }
        fun missingPlugin(pluginName: String) = launch {
            val profileName = profileName
            broadcast { it.missingPlugin(profileName, pluginName) }
        }
        override fun close() {
            callbacks.kill()
            cancel()
            data = null
        }
    }
    interface Interface {
        val data: Data
        val tag: String
        fun createNotification(profileName: String): ServiceNotification
        fun onBind(intent: Intent): IBinder? =
            if (intent.action == Action.SERVICE) data.binder else null
        fun reload() {
            val selected = DataStore.selectedProxy
            val selectedExists = selected > 0L && SagerDatabase.proxyDao.getById(selected) != null
            if (!selectedExists) {
                val all = SagerDatabase.proxyDao.getAll()
                val auto = all
                    .firstOrNull { GroupManager.isDefaultAutoSelectConfig(it) }
                val fallback = auto ?: all.firstOrNull()
                if (fallback != null) {
                    DataStore.selectedProxy = fallback.id
                    DataStore.currentProfile = fallback.id
                } else {
                    stopRunner(false, (this as Context).getString(R.string.profile_empty))
                    return
                }
            }
            if (canReloadSelector()) {
                val ent = SagerDatabase.proxyDao.getById(DataStore.selectedProxy)
                val tag = data.proxy!!.config.profileTagMap[ent?.id] ?: ""
                if (tag.isNotBlank() && ent != null) {
                    // select from GUI
                    data.proxy!!.box.selectOutbound(tag)
                    // or select from webui
                    // => selector_OnProxySelected
                }
                return
            }
            val s = data.state
            when {
                s == State.Stopped -> startRunner()
                s.canStop -> stopRunner(true)
                else -> Logs.w("Illegal state $s when invoking use")
            }
        }
        fun canReloadSelector(): Boolean {
            if ((data.proxy?.config?.selectorGroupId ?: -1L) < 0) return false
            val ent = SagerDatabase.proxyDao.getById(DataStore.selectedProxy) ?: return false
            if (DataStore.isSmartPreferredOrderDirty(ent.groupId)) return false
            val tmpBox = ProxyInstance(ent)
            tmpBox.buildConfigTmp()
            if (tmpBox.lastSelectorGroupId == data.proxy?.lastSelectorGroupId) {
                return true
            }
            return false
        }
        suspend fun startProcesses() {
            data.proxy!!.launch()
        }
        fun startRunner() {
            this as Context
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(Intent(this, javaClass))
            else startService(Intent(this, javaClass))
        }
        fun killProcesses() {
            data.proxy?.close()
            wakeLock?.apply {
                release()
                wakeLock = null
            }
            runOnDefaultDispatcher {
                DefaultNetworkListener.stop(this)
            }
        }
        fun stopRunner(restart: Boolean = false, msg: String? = null) {
            DataStore.baseService = null
            DataStore.vpnService = null
            if (data.state == State.Stopping) return
            data.notification?.destroy()
            data.notification = null
            this as Service
            data.changeState(State.Stopping)
            runOnMainDispatcher {
                suspend fun cancelJobBounded(name: String, job: Job?) {
                    if (job == null) return
                    job.cancel()
                    val joined = withTimeoutOrNull(1500L) {
                        job.join()
                        true
                    } ?: false
                    if (!joined) Logs.w("Timed out while stopping $name job, forcing shutdown")
                }
                runCatching {
                    cancelJobBounded("connecting", data.connectingJob) // ensure stop connecting first
                    cancelJobBounded("smart-switch", data.smartSwitchJob)
                }.onFailure {
                    Logs.w("Failed while cancelling jobs during stop: ${it.readableMessage}")
                }
                try {
                    killProcesses()
                } catch (e: Exception) {
                    Logs.w("Failed while killing processes during stop: ${e.readableMessage}")
                } finally {
                    val stopData = data
                    if (stopData.closeReceiverRegistered) {
                        runCatching {
                            unregisterReceiver(stopData.receiver)
                        }.onFailure {
                            Logs.w("Failed to unregister close receiver: ${it.readableMessage}")
                        }
                        stopData.closeReceiverRegistered = false
                    }
                    stopData.proxy = null
                    stopData.connectingJob = null
                    stopData.smartSwitchJob = null
                }
                // change the state
                data.changeState(State.Stopped, msg)
                // stop the service if nothing has bound to it
                if (restart) startRunner() else {
                    stopSelf()
                }
            }
        }
        fun persistStats() {
            // TODO NEW save app stats?
        }
        // networks
        var upstreamInterfaceName: String?
        suspend fun preInit() {
            DefaultNetworkListener.start(this) {
                SagerNet.connectivity.getLinkProperties(it)?.also { link ->
                    SagerNet.underlyingNetwork = it
                    DataStore.vpnService?.updateUnderlyingNetwork()
                    //
                    val oldName = upstreamInterfaceName
                    if (oldName != link.interfaceName) {
                        upstreamInterfaceName = link.interfaceName
                    }
                    if (oldName != null && upstreamInterfaceName != null && oldName != upstreamInterfaceName) {
                        Logs.d("Network changed: $oldName -> $upstreamInterfaceName")
                        if (DataStore.networkChangeResetConnections) {
                            Libcore.resetAllConnections(true)
                        }
                    }
                }
            }
        }
        var wakeLock: PowerManager.WakeLock?
        fun acquireWakeLock()
        suspend fun lateInit() {
            wakeLock?.apply {
                release()
                wakeLock = null
            }
            if (DataStore.acquireWakeLock) {
                acquireWakeLock()
                data.notification?.postNotificationWakeLockStatus(true)
            } else {
                data.notification?.postNotificationWakeLockStatus(false)
            }
        }
        fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
            DataStore.baseService = this
            val data = data
            if (data.state != State.Stopped) return Service.START_NOT_STICKY
            val profile = SagerDatabase.proxyDao.getById(DataStore.selectedProxy)
            this as Context
            if (profile == null) { // gracefully shutdown: https://stackoverflow.com/q/47337857/2245107
                data.notification = createNotification("")
                stopRunner(false, getString(R.string.profile_empty))
                return Service.START_NOT_STICKY
            }
            val proxy = ProxyInstance(profile, this)
            data.proxy = proxy
            BootReceiver.enabled = DataStore.persistAcrossReboot
            if (!data.closeReceiverRegistered) {
                val filter = IntentFilter().apply {
                    addAction(Action.RELOAD)
                    addAction(Intent.ACTION_SHUTDOWN)
                    addAction(Action.CLOSE)
                    // addAction(Action.SWITCH_WAKE_LOCK)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
                    }
                    addAction(Action.RESET_UPSTREAM_CONNECTIONS)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    registerReceiver(
                        data.receiver,
                        filter,
                        "$packageName.SERVICE",
                        null,
                        Context.RECEIVER_EXPORTED
                    )
                } else {
                    registerReceiver(
                        data.receiver,
                        filter,
                        "$packageName.SERVICE",
                        null
                    )
                }
                data.closeReceiverRegistered = true
            }
            data.changeState(State.Connecting)
            runOnMainDispatcher {
                try {
                    data.notification = createNotification(ServiceNotification.genTitle(profile))
                    Executable.killAll()    // clean up old processes
                    preInit()
                    proxy.init()
                    DataStore.currentProfile = profile.id
                    proxy.processes = GuardedProcessPool {
                        Logs.w(it)
                        stopRunner(false, it.readableMessage)
                    }
                    startProcesses()
                    data.changeState(State.Connected)
                    if (GroupManager.isAutoSelectAggregate(profile)) {
                        runOnDefaultDispatcher {
                            val cooldownMs =
                                DataStore.smartSwitchCooldownSec.coerceIn(30, 900) * 1000L
                            val minDwellMs =
                                DataStore.smartSwitchMinDwellSec.coerceIn(30, 1200) * 1000L
                            val normalProbeMs =
                                DataStore.smartSwitchProbeIntervalSec.coerceIn(10, 120) * 1000L
                            val badProbeMs =
                                DataStore.smartSwitchBadProbeIntervalSec.coerceIn(5, 60) * 1000L
                            val warmupRounds = DataStore.smartSwitchWarmupRounds.coerceIn(1, 8)
                            val baseWins = DataStore.smartSwitchCandidateWins.coerceIn(2, 10)
                            val warmupWins =
                                DataStore.smartSwitchCandidateWinsWarmup.coerceIn(1, 5)
                            val minImproveAbs =
                                DataStore.smartSwitchMinImproveAbs.coerceIn(80, 1200)
                            val minImprovePct =
                                DataStore.smartSwitchMinImprovePct.coerceIn(8, 60)
                            val weakScore = DataStore.smartSwitchWeakScore.coerceIn(600, 3000)
                            val criticalScore =
                                DataStore.smartSwitchCriticalScore.coerceIn(800, 5000)
                            val failTrigger =
                                DataStore.smartSwitchFailStreakTrigger.coerceIn(1, 10)
                            val stableLockMs =
                                DataStore.smartSwitchStableLockSec.coerceIn(120, 3600) * 1000L
                            val excellentScore =
                                DataStore.smartSwitchExcellentScore.coerceIn(450, 1400)
                            val minThroughputGainPct =
                                DataStore.smartSwitchMinThroughputGainPct.coerceIn(5, 80)
                            val conservativeSwitch = DataStore.smartConservativeSwitchEnabled
                            val conservativeMaxSwitches10Min =
                                DataStore.smartConservativeMaxSwitches10Min.coerceIn(1, 8)
                            val disruptionHoldMinMs =
                                DataStore.smartDisruptionHoldMinSec.coerceIn(30, 900) * 1000L
                            val disruptionHoldMaxMs =
                                DataStore.smartDisruptionHoldMaxSec.coerceIn(60, 1800) * 1000L
                            val effectiveCooldownMs = if (conservativeSwitch) {
                                (cooldownMs * 3L / 2L).coerceAtMost(1_800_000L)
                            } else {
                                cooldownMs
                            }
                            val effectiveStableLockMs = if (conservativeSwitch) {
                                (stableLockMs * 3L / 2L).coerceAtMost(4_200_000L)
                            } else {
                                stableLockMs
                            }
                            val effectiveMinImproveAbs = if (conservativeSwitch) {
                                (minImproveAbs + 140).coerceAtMost(2000)
                            } else {
                                minImproveAbs
                            }
                            val effectiveMinImprovePct = if (conservativeSwitch) {
                                (minImprovePct + 6).coerceAtMost(75)
                            } else {
                                minImprovePct
                            }
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
                            val recentSwitchesMs = ArrayDeque<Long>()
                            val learningEnabled = DataStore.smartEnableNetworkLearning
                            fun activeStats(): Pair<Int, Int> {
                                if (activeId <= 0L) return Pair(-1, 0)
                                return Pair(
                                    DataStore.getSmartLastScore(activeId),
                                    DataStore.getSmartFailureStreak(activeId)
                                )
                            }
                            fun bandwidth(profileId: Long): Int {
                                if (profileId <= 0L) return -1
                                return DataStore.getSmartLastBandwidthKbps(profileId)
                            }
                            fun currentScope(): String {
                                if (!learningEnabled) return "default"
                                return upstreamInterfaceName?.takeIf { it.isNotBlank() } ?: "default"
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
                                DataStore.smartSessionHealth =
                                    (latencyPart + throughputPart - streakPenalty).coerceIn(0, 100)
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
                                recentSwitchesMs.addLast(activeSinceMs)
                                val keepFrom = activeSinceMs - 600_000L
                                while (recentSwitchesMs.isNotEmpty() && recentSwitchesMs.first() < keepFrom) {
                                    recentSwitchesMs.removeFirst()
                                }
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
                                val activeCritical = isCritical(activeScore, activeStreak)
                                val activeWeak = isWeak(activeScore, activeStreak)
                                val activeGood = activeScore in 1..excellentScore && activeStreak == 0
                                val activeBw = bandwidth(activeId)
                                val candidateBw = bandwidth(id)
                                if (!warmup && !activeCritical && now < disruptionUntilMs) {
                                    setDecision("hold:disruption_window")
                                    return
                                }
                                if (!warmup && !activeCritical && now - lastSwitchAtMs < effectiveCooldownMs) return
                                if (!activeCritical && now - activeSinceMs < minDwellMs) return
                                if (!warmup && activeGood && now - activeSinceMs < effectiveStableLockMs) {
                                    setDecision("hold:stable_lock")
                                    return
                                }
                                if (!warmup && !activeCritical && conservativeSwitch) {
                                    val keepFrom = now - 600_000L
                                    while (recentSwitchesMs.isNotEmpty() && recentSwitchesMs.first() < keepFrom) {
                                        recentSwitchesMs.removeFirst()
                                    }
                                    if (recentSwitchesMs.size >= conservativeMaxSwitches10Min) {
                                        setDecision("hold:conservative_switch_budget")
                                        return
                                    }
                                }
                                val improveAbs = if (activeScore > 0) activeScore - candidateScore else Int.MAX_VALUE
                                val improvePctEnough =
                                    activeScore <= 0 || candidateScore * 100 <= activeScore * (100 - effectiveMinImprovePct)
                                val improveAbsEnough = activeScore <= 0 || improveAbs >= effectiveMinImproveAbs
                                val throughputGainEnough = if (activeBw > 0 && candidateBw > 0) {
                                    candidateBw * 100 >= activeBw * (100 + minThroughputGainPct)
                                } else {
                                    false
                                }
                                val activeExcellent = activeGood
                                val improveEnough = when {
                                    activeCritical -> true
                                    activeExcellent -> {
                                        val strictAbs = effectiveMinImproveAbs + 180
                                        val strictPct = (effectiveMinImprovePct + 8).coerceAtMost(78)
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
                                }.let { base ->
                                    if (conservativeSwitch && !activeCritical) base + 1 else base
                                }.coerceAtLeast(1)
                                if (pendingWins < requiredWins) return
                                if (selectOutboundById(id)) {
                                    pendingCandidateId = 0L
                                    pendingWins = 0
                                }
                            }
                            val scopedPreferredId =
                                DataStore.getSmartPreferredProxyScoped(currentScope(), profile.groupId)
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
                            data.smartSwitchJob?.cancel()
                            data.smartSwitchJob = runOnDefaultDispatcher {
                                repeat(warmupRounds) {
                                    delay(badProbeMs)
                                    if (DataStore.serviceState != State.Connected) return@runOnDefaultDispatcher
                                    val id = SmartSelector.selectBestFast(profile.groupId, currentScope()) ?: return@repeat
                                    maybeSwitchTo(id, warmup = true)
                                }
                                while (DataStore.serviceState == State.Connected) {
                                    val now = System.currentTimeMillis()
                                    val (score, streak) = activeStats()
                                    val weak = isWeak(score, streak)
                                    val critical = isCritical(score, streak)
                                    updateSessionHealth(score, streak, bandwidth(activeId))
                                    if (now - lastAutoTuneAtMs >= 180_000L) {
                                        lastAutoTuneAtMs = now
                                        val health = DataStore.smartSessionHealth
                                        if (health < 35 && DataStore.connectionTestConcurrent < 32) {
                                            DataStore.connectionTestConcurrent =
                                                (DataStore.connectionTestConcurrent + 2).coerceAtMost(32)
                                            setDecision("tune:raise_probe_concurrency")
                                        } else if (health > 85 && DataStore.connectionTestConcurrent > 14) {
                                            DataStore.connectionTestConcurrent =
                                                (DataStore.connectionTestConcurrent - 1).coerceAtLeast(14)
                                            setDecision("tune:lower_probe_concurrency")
                                        }
                                    }
                                    if (!weak && score in 1..excellentScore && streak == 0) {
                                        stableRounds = (stableRounds + 1).coerceAtMost(120)
                                    } else {
                                        stableRounds = 0
                                    }
                                    criticalRounds = if (critical) {
                                        (criticalRounds + 1).coerceAtMost(60)
                                    } else {
                                        0
                                    }
                                    val stabilityMultiplier = when {
                                        stableRounds >= 24 -> 4L
                                        stableRounds >= 12 -> 3L
                                        stableRounds >= 6 -> 2L
                                        else -> 1L
                                    }
                                    val delayMs = if (weak) {
                                        badProbeMs
                                    } else {
                                        normalProbeMs * stabilityMultiplier
                                    }
                                    delay(delayMs)
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
                    lateInit()
                } catch (_: CancellationException) { // if the job was cancelled, it is canceller's responsibility to call stopRunner
                } catch (_: UnknownHostException) {
                    stopRunner(false, getString(R.string.invalid_server))
                } catch (e: PluginManager.PluginNotFoundException) {
                    Toast.makeText(this@Interface, e.readableMessage, Toast.LENGTH_SHORT).show()
                    Logs.w(e)
                    data.binder.missingPlugin(e.plugin)
                    stopRunner(false, null)
                } catch (exc: Throwable) {
                    if (exc.javaClass.name.endsWith("proxyerror")) {
                        // error from golang
                        Logs.w(exc.readableMessage)
                    } else {
                        Logs.w(exc)
                    }
                    stopRunner(
                        false, "${getString(R.string.service_failed)}: ${exc.readableMessage}"
                    )
                } finally {
                    data.connectingJob = null
                }
            }
            return Service.START_NOT_STICKY
        }
    }
}
