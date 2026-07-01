package io.nekohasekai.sagernet.database

import android.os.Binder
import androidx.preference.PreferenceDataStore
import io.nekohasekai.sagernet.CONNECTION_TEST_URL
import io.nekohasekai.sagernet.DEFAULT_SUBSCRIPTION_LINK
import io.nekohasekai.sagernet.GroupType
import io.nekohasekai.sagernet.IPv6Mode
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.TunImplementation
import io.nekohasekai.sagernet.bg.BaseService
import io.nekohasekai.sagernet.bg.VpnService
import io.nekohasekai.sagernet.database.preference.OnPreferenceDataStoreChangeListener
import io.nekohasekai.sagernet.database.preference.PublicDatabase
import io.nekohasekai.sagernet.database.preference.RoomPreferenceDataStore
import io.nekohasekai.sagernet.ktx.boolean
import io.nekohasekai.sagernet.ktx.int
import io.nekohasekai.sagernet.ktx.long
import io.nekohasekai.sagernet.ktx.parsePort
import io.nekohasekai.sagernet.ktx.string
import io.nekohasekai.sagernet.ktx.stringToInt
import io.nekohasekai.sagernet.ktx.stringToIntIfExists
import moe.matsuri.nb4a.TempDatabase

object DataStore : OnPreferenceDataStoreChangeListener {

    // share service state in main & bg process
    @Volatile
    var serviceState = BaseService.State.Idle

    // internal proxy state (hidden from UI)
    @Volatile
    var internalProxyActive = false
    @Volatile
    var internalProxyProfileId: Long = 0L
    @Volatile
    var internalProxyUserSelected: Long = 0L

    val configurationStore = RoomPreferenceDataStore(PublicDatabase.kvPairDao)
    val profileCacheStore = RoomPreferenceDataStore(TempDatabase.profileCacheDao)

    // last used, but may not be running
    var currentProfile by configurationStore.long(Key.PROFILE_CURRENT)
    var lastConnectedProfile by configurationStore.long(Key.PROFILE_LAST_CONNECTED)

    var selectedProxy by configurationStore.long(Key.PROFILE_ID)
    var selectedGroup by configurationStore.long(Key.PROFILE_GROUP) { currentGroupId() } // "ungrouped" group id = 1

    // only in bg process
    var vpnService: VpnService? = null
    var baseService: BaseService.Interface? = null

    // main

    var runningTest = false

    fun clearInternalProxyState() {
        internalProxyActive = false
        internalProxyProfileId = 0L
        internalProxyUserSelected = 0L
    }

    fun restoreInternalProxySelection() {
        val profileId = internalProxyUserSelected
        if (profileId > 0L) {
            syncSelectedProfile(profileId)
        }
    }

    fun syncSelectedProfile(profileId: Long) {
        selectedProxy = profileId
        currentProfile = profileId
        lastConnectedProfile = profileId
    }

    fun hasValidProfile(profileId: Long): Boolean {
        return profileId > 0L && SagerDatabase.proxyDao.getById(profileId) != null
    }

    fun resolvePreferredProfileId(vararg candidates: Long): Long? {
        for (candidate in candidates) {
            if (hasValidProfile(candidate)) return candidate
        }
        val all = SagerDatabase.proxyDao.getAll()
        val auto = all.firstOrNull { GroupManager.isDefaultAutoSelectConfig(it) }
        return (auto ?: all.firstOrNull())?.id
    }

    fun currentGroupId(): Long = currentGroup().id

    fun currentGroup(): ProxyGroup {
        val currentSelected = configurationStore.getLong(Key.PROFILE_GROUP, -1)
        if (currentSelected > 0L) {
            SagerDatabase.groupDao.getById(currentSelected)?.also {
                selectedGroup = it.id
                return it
            }
        }
        val group = SagerDatabase.groupDao.allGroups().firstOrNull()
            ?: ProxyGroup(ungrouped = true).apply {
                id = SagerDatabase.groupDao.createGroup(this)
            }
        selectedGroup = group.id
        return group
    }

    fun selectedGroupForImport(): Long {
        val current = currentGroup()
        if (current.type == GroupType.BASIC) return current.id
        val groups = SagerDatabase.groupDao.allGroups()
        return groups.firstOrNull { it.type == GroupType.BASIC }?.id
            ?: current.id
    }

    var appTLSVersion by configurationStore.string(Key.APP_TLS_VERSION)
    var enableClashAPI by configurationStore.boolean(Key.ENABLE_CLASH_API) { true }
    var showBottomBar by configurationStore.boolean(Key.SHOW_BOTTOM_BAR)

    var allowInsecureOnRequest by configurationStore.boolean(Key.ALLOW_INSECURE_ON_REQUEST)
    var networkChangeResetConnections by configurationStore.boolean(Key.NETWORK_CHANGE_RESET_CONNECTIONS) { true }
    var wakeResetConnections by configurationStore.boolean(Key.WAKE_RESET_CONNECTIONS) { true }

    //

    var isExpert by configurationStore.boolean(Key.APP_EXPERT)
    var appTheme by configurationStore.int(Key.APP_THEME)
    var nightTheme by configurationStore.stringToInt(Key.NIGHT_THEME)
    var serviceMode by configurationStore.string(Key.SERVICE_MODE) { Key.MODE_VPN }

    var trafficSniffing by configurationStore.stringToInt(Key.TRAFFIC_SNIFFING) { 2 }
    var resolveDestination by configurationStore.boolean(Key.RESOLVE_DESTINATION) { true }

    var mtu by configurationStore.stringToInt(Key.MTU) { 9000 }

    var bypassLan by configurationStore.boolean(Key.BYPASS_LAN) { true }
    var bypassLanInCore by configurationStore.boolean(Key.BYPASS_LAN_IN_CORE) { true }

    var allowAccess by configurationStore.boolean(Key.ALLOW_ACCESS)
    var speedInterval by configurationStore.stringToInt(Key.SPEED_INTERVAL) { 1000 }
    var showGroupInNotification by configurationStore.boolean("showGroupInNotification")

    var globalCustomConfig by configurationStore.string(Key.GLOBAL_CUSTOM_CONFIG) { "" }

    var remoteDns by configurationStore.string(Key.REMOTE_DNS) {
        "https://cloudflare-dns.com/dns-query\nhttps://dns.google/dns-query"
    }
    var directDns by configurationStore.string(Key.DIRECT_DNS) {
        "https://223.5.5.5/dns-query\nhttps://1.1.1.1/dns-query"
    }
    var enableDnsRouting by configurationStore.boolean(Key.ENABLE_DNS_ROUTING) { true }
    var enableFakeDns by configurationStore.boolean(Key.ENABLE_FAKEDNS) { true }

    var rulesProvider by configurationStore.stringToInt(Key.RULES_PROVIDER)
    var logLevel by configurationStore.stringToInt(Key.LOG_LEVEL)
    var logBufSize by configurationStore.int(Key.LOG_BUF_SIZE) { 0 }
    var acquireWakeLock by configurationStore.boolean(Key.ACQUIRE_WAKE_LOCK)

    // hopefully hashCode = mHandle doesn't change, currently this is true from KitKat to Nougat
    private val userIndex by lazy { Binder.getCallingUserHandle().hashCode() }
    var mixedPort: Int
        get() = getLocalPort(Key.MIXED_PORT, 2080)
        set(value) = saveLocalPort(Key.MIXED_PORT, value)

    fun initGlobal() {
        if (configurationStore.getString(Key.MIXED_PORT) == null) {
            mixedPort = mixedPort
        }
    }

    fun applyManagedSettingsDefaults() {
        initGlobal()

        serviceMode = Key.MODE_VPN
        clientMode = false
        persistAcrossReboot = false
        networkChangeResetConnections = true
        wakeResetConnections = true

        allowAccess = false
        appendHttpProxy = false
        globalAllowInsecure = false
        allowInsecureOnRequest = false

        trafficSniffing = 2
        resolveDestination = true
        bypassLan = true
        bypassLanInCore = true

        enableDnsRouting = true
        enableFakeDns = true
        if (remoteDns.isBlank()) {
            remoteDns = "https://cloudflare-dns.com/dns-query\nhttps://dns.google/dns-query"
        }
        if (directDns.isBlank()) {
            directDns = "https://223.5.5.5/dns-query\nhttps://1.1.1.1/dns-query"
        }

        enableClashAPI = true
        profileTrafficStatistics = true
        showDirectSpeed = true
        smartEnableNetworkLearning = true
        smartAdaptiveTransportEnabled = true
        smartSpeedRefineEnabled = true
        smartQuarantineEnabled = true
        smartDebugEnabled = false
        autoSelectPrimary = "parallel"
        if (smartProfilePreset == "manual") smartProfilePreset = "balanced"
    }


    private fun getLocalPort(key: String, default: Int): Int {
        return parsePort(configurationStore.getString(key), default + userIndex)
    }

    private fun saveLocalPort(key: String, value: Int) {
        configurationStore.putString(key, "$value")
    }

    var ipv6Mode by configurationStore.stringToInt(Key.IPV6_MODE) { IPv6Mode.DISABLE }

    var meteredNetwork by configurationStore.boolean(Key.METERED_NETWORK)
    var proxyApps by configurationStore.boolean(Key.PROXY_APPS)
    var bypass by configurationStore.boolean(Key.BYPASS_MODE) { true }
    var individual by configurationStore.string(Key.INDIVIDUAL)
    var showDirectSpeed by configurationStore.boolean(Key.SHOW_DIRECT_SPEED) { true }

    var persistAcrossReboot by configurationStore.boolean(Key.PERSIST_ACROSS_REBOOT) { false }

    var appendHttpProxy by configurationStore.boolean(Key.APPEND_HTTP_PROXY)
    var connectionTestURL by configurationStore.string(Key.CONNECTION_TEST_URL) { CONNECTION_TEST_URL }
    var connectionTestConcurrent by configurationStore.int("connectionTestConcurrent") { 20 }
    var parallelStrategy by configurationStore.string(Key.PARALLEL_STRATEGY) { "race" }
    var parallelConcurrency by configurationStore.int(Key.PARALLEL_CONCURRENCY) { 24 }
    var parallelDelayMs by configurationStore.int(Key.PARALLEL_DELAY) { 120 }
    var parallelTimeoutMs by configurationStore.int(Key.PARALLEL_TIMEOUT) { 8000 }
    var parallelUrl by configurationStore.string(Key.PARALLEL_URL) {
        "https://speed.cloudflare.com/__down?bytes=1000000"
    }
    var parallelIntervalSec by configurationStore.int(Key.PARALLEL_INTERVAL) { 30 }
    var parallelIdleTimeoutMin by configurationStore.int(Key.PARALLEL_IDLE_TIMEOUT) { 30 }
    var parallelTolerance by configurationStore.int(Key.PARALLEL_TOLERANCE) { 20 }
    var autoSelectPrimary by configurationStore.string(Key.AUTO_SELECT_PRIMARY) { "parallel" }
    var smartSwitchCooldownSec by configurationStore.int("smartSwitchCooldownSec") { 45 }
    var smartSwitchMinDwellSec by configurationStore.int("smartSwitchMinDwellSec") { 45 }
    var smartSwitchProbeIntervalSec by configurationStore.int("smartSwitchProbeIntervalSec") { 20 }
    var smartSwitchBadProbeIntervalSec by configurationStore.int("smartSwitchBadProbeIntervalSec") { 6 }
    var smartSwitchWarmupRounds by configurationStore.int("smartSwitchWarmupRounds") { 3 }
    var smartSwitchCandidateWins by configurationStore.int("smartSwitchCandidateWins") { 2 }
    var smartSwitchCandidateWinsWarmup by configurationStore.int("smartSwitchCandidateWinsWarmup") { 2 }
    var smartSwitchMinImproveAbs by configurationStore.int("smartSwitchMinImproveAbs") { 260 }
    var smartSwitchMinImprovePct by configurationStore.int("smartSwitchMinImprovePct") { 20 }
    var smartSwitchWeakScore by configurationStore.int("smartSwitchWeakScore") { 1100 }
    var smartSwitchCriticalScore by configurationStore.int("smartSwitchCriticalScore") { 1500 }
    var smartSwitchFailStreakTrigger by configurationStore.int("smartSwitchFailStreakTrigger") { 2 }
    var smartSwitchStableLockSec by configurationStore.int("smartSwitchStableLockSec") { 300 }
    var smartSwitchExcellentScore by configurationStore.int("smartSwitchExcellentScore") { 760 }
    var smartSwitchMinThroughputGainPct by configurationStore.int("smartSwitchMinThroughputGainPct") { 18 }
    var smartProfilePreset by configurationStore.string("smartProfilePreset") { "balanced" }
    var smartSwitchSensitivity by configurationStore.string("smartSwitchSensitivity") { "balanced" }
    var smartSwitchNotificationsEnabled by configurationStore.boolean("smartSwitchNotificationsEnabled") { true }
    var smartInterruptExistingConnections by configurationStore.boolean("smartInterruptExistingConnections") { true }
    var smartActiveProxyId by configurationStore.long("smartActiveProxyId")
    var smartRuntimeGroupId: Long = 0L
    var smartStandbyProxyId: Long = 0L
    var smartEnableNetworkLearning by configurationStore.boolean("smartEnableNetworkLearning") { true }
    var smartDebugEnabled by configurationStore.boolean("smartDebugEnabled") { false }
    var smartSessionHealth by configurationStore.int("smartSessionHealth") { 0 }
    var smartLastDecision by configurationStore.string("smartLastDecision") { "idle" }
    var smartAdaptiveTransportEnabled by configurationStore.boolean("smartAdaptiveTransportEnabled") { true }
    var smartTransportPenaltyStep by configurationStore.int("smartTransportPenaltyStep") { 160 }
    var smartTransportPenaltyDecay by configurationStore.int("smartTransportPenaltyDecay") { 90 }
    var smartTransportPenaltyCeil by configurationStore.int("smartTransportPenaltyCeil") { 2400 }
    var smartSpeedRefineEnabled by configurationStore.boolean("smartSpeedRefineEnabled") { true }
    var smartSpeedRefineTopN by configurationStore.int("smartSpeedRefineTopN") { 4 }
    var smartSpeedRefineTimeoutMs by configurationStore.int("smartSpeedRefineTimeoutMs") { 2600 }
    var smartDisruptionHoldMinSec by configurationStore.int("smartDisruptionHoldMinSec") { 90 }
    var smartDisruptionHoldMaxSec by configurationStore.int("smartDisruptionHoldMaxSec") { 300 }
    var smartQuarantineEnabled by configurationStore.boolean("smartQuarantineEnabled") { true }
    var smartQuarantineShortMin by configurationStore.int("smartQuarantineShortMin") { 10 }
    var smartQuarantineMediumMin by configurationStore.int("smartQuarantineMediumMin") { 60 }
    var smartQuarantineLongMin by configurationStore.int("smartQuarantineLongMin") { 360 }
    var alwaysShowAddress by configurationStore.boolean(Key.ALWAYS_SHOW_ADDRESS)

    data class SmartAdaptivePolicy(
        val cooldownSec: Int,
        val minDwellSec: Int,
        val probeIntervalSec: Int,
        val badProbeIntervalSec: Int,
        val warmupRounds: Int,
        val candidateWins: Int,
        val candidateWinsWarmup: Int,
        val minImproveAbs: Int,
        val minImprovePct: Int,
        val weakScore: Int,
        val criticalScore: Int,
        val failStreakTrigger: Int,
        val stableLockSec: Int,
        val excellentScore: Int,
        val minThroughputGainPct: Int,
        val disruptionHoldMinSec: Int,
        val disruptionHoldMaxSec: Int,
    )

    var smartMainTxRate: Long = 0L

    var smartMainRxRate: Long = 0L

    var tunImplementation by configurationStore.stringToInt(Key.TUN_IMPLEMENTATION) { TunImplementation.GVISOR }
    var profileTrafficStatistics by configurationStore.boolean(Key.PROFILE_TRAFFIC_STATISTICS) { true }

    var yacdURL by configurationStore.string("yacdURL") { "http://127.0.0.1:9090/ui" }
    var yacdSelectedGroup by configurationStore.string("yacdSelectedGroup") { "" }
    var yacdSelectedProxy by configurationStore.string("yacdSelectedProxy") { "" }
    var yacdSelectedFlag by configurationStore.string("yacdSelectedFlag") { "" }
    var yacdCachedLocations by configurationStore.string("yacdCachedLocations") { "[]" }
    var internalBrowserUrl by configurationStore.string("internalBrowserUrl") { "https://www.google.com" }
    var clientMode by configurationStore.boolean("clientMode") { false }

    // protocol

    var globalAllowInsecure by configurationStore.boolean(Key.GLOBAL_ALLOW_INSECURE) { false }

    // old cache, DO NOT ADD

    var dirty by profileCacheStore.boolean(Key.PROFILE_DIRTY)
    var editingId by profileCacheStore.long(Key.PROFILE_ID)
    var editingGroup by profileCacheStore.long(Key.PROFILE_GROUP)
    var profileName by profileCacheStore.string(Key.PROFILE_NAME)
    var serverAddress by profileCacheStore.string(Key.SERVER_ADDRESS)
    var serverPort by profileCacheStore.stringToInt(Key.SERVER_PORT)
    var serverPorts by profileCacheStore.string("serverPorts")
    var serverUsername by profileCacheStore.string(Key.SERVER_USERNAME)
    var serverPassword by profileCacheStore.string(Key.SERVER_PASSWORD)
    var serverPassword1 by profileCacheStore.string(Key.SERVER_PASSWORD1)
    var serverMethod by profileCacheStore.string(Key.SERVER_METHOD)

    var sharedStorage by profileCacheStore.string("sharedStorage")

    var serverProtocol by profileCacheStore.string(Key.SERVER_PROTOCOL)
    var serverObfs by profileCacheStore.string(Key.SERVER_OBFS)

    var serverNetwork by profileCacheStore.string(Key.SERVER_NETWORK)
    var serverHost by profileCacheStore.string(Key.SERVER_HOST)
    var serverPath by profileCacheStore.string(Key.SERVER_PATH)
    var serverSNI by profileCacheStore.string(Key.SERVER_SNI)
    var serverEncryption by profileCacheStore.string(Key.SERVER_ENCRYPTION)
    var serverALPN by profileCacheStore.string(Key.SERVER_ALPN)
    var serverCertificates by profileCacheStore.string(Key.SERVER_CERTIFICATES)
    var serverMTU by profileCacheStore.stringToInt(Key.SERVER_MTU)
    var serverHeaders by profileCacheStore.string(Key.SERVER_HEADERS)
    var serverAllowInsecure by profileCacheStore.boolean(Key.SERVER_ALLOW_INSECURE)

    var serverAuthType by profileCacheStore.stringToInt(Key.SERVER_AUTH_TYPE)
    var serverUploadSpeed by profileCacheStore.stringToInt(Key.SERVER_UPLOAD_SPEED)
    var serverDownloadSpeed by profileCacheStore.stringToInt(Key.SERVER_DOWNLOAD_SPEED)
    var serverStreamReceiveWindow by profileCacheStore.stringToIntIfExists(Key.SERVER_STREAM_RECEIVE_WINDOW)
    var serverConnectionReceiveWindow by profileCacheStore.stringToIntIfExists(Key.SERVER_CONNECTION_RECEIVE_WINDOW)
    var serverDisableMtuDiscovery by profileCacheStore.boolean(Key.SERVER_DISABLE_MTU_DISCOVERY)
    var serverHopInterval by profileCacheStore.stringToInt(Key.SERVER_HOP_INTERVAL) { 10 }

    var protocolVersion by profileCacheStore.stringToInt(Key.PROTOCOL_VERSION) { 2 } // default is SOCKS5

    var serverProtocolInt by profileCacheStore.stringToInt(Key.SERVER_PROTOCOL)
    var serverPrivateKey by profileCacheStore.string(Key.SERVER_PRIVATE_KEY)
    var serverInsecureConcurrency by profileCacheStore.stringToInt(Key.SERVER_INSECURE_CONCURRENCY)

    var serverUDPRelayMode by profileCacheStore.string(Key.SERVER_UDP_RELAY_MODE)
    var serverCongestionController by profileCacheStore.string(Key.SERVER_CONGESTION_CONTROLLER)
    var serverDisableSNI by profileCacheStore.boolean(Key.SERVER_DISABLE_SNI)
    var serverReduceRTT by profileCacheStore.boolean(Key.SERVER_REDUCE_RTT)

    var routeName by profileCacheStore.string(Key.ROUTE_NAME)
    var routeDomain by profileCacheStore.string(Key.ROUTE_DOMAIN)
    var routeIP by profileCacheStore.string(Key.ROUTE_IP)
    var routePort by profileCacheStore.string(Key.ROUTE_PORT)
    var routeSourcePort by profileCacheStore.string(Key.ROUTE_SOURCE_PORT)
    var routeNetwork by profileCacheStore.string(Key.ROUTE_NETWORK)
    var routeSource by profileCacheStore.string(Key.ROUTE_SOURCE)
    var routeProtocol by profileCacheStore.string(Key.ROUTE_PROTOCOL)
    var routeOutbound by profileCacheStore.stringToInt(Key.ROUTE_OUTBOUND)
    var routeOutboundRule by profileCacheStore.long(Key.ROUTE_OUTBOUND + "Long")
    var routePackages by profileCacheStore.string(Key.ROUTE_PACKAGES)

    var frontProxy by profileCacheStore.long(Key.GROUP_FRONT_PROXY + "Long")
    var landingProxy by profileCacheStore.long(Key.GROUP_LANDING_PROXY + "Long")
    var frontProxyTmp by profileCacheStore.stringToInt(Key.GROUP_FRONT_PROXY)
    var landingProxyTmp by profileCacheStore.stringToInt(Key.GROUP_LANDING_PROXY)

    var serverConfig by profileCacheStore.string(Key.SERVER_CONFIG)
    var serverCustom by profileCacheStore.string(Key.SERVER_CUSTOM)
    var serverCustomOutbound by profileCacheStore.string(Key.SERVER_CUSTOM_OUTBOUND)

    var groupName by profileCacheStore.string(Key.GROUP_NAME)
    var groupType by profileCacheStore.stringToInt(Key.GROUP_TYPE)
    var groupOrder by profileCacheStore.stringToInt(Key.GROUP_ORDER)
    var groupIsSelector by profileCacheStore.boolean(Key.GROUP_IS_SELECTOR)

    var subscriptionLink by profileCacheStore.string(Key.SUBSCRIPTION_LINK) { DEFAULT_SUBSCRIPTION_LINK }
    var subscriptionForceResolve by profileCacheStore.boolean(Key.SUBSCRIPTION_FORCE_RESOLVE)
    var subscriptionDeduplication by profileCacheStore.boolean(Key.SUBSCRIPTION_DEDUPLICATION)
    var subscriptionUpdateWhenConnectedOnly by profileCacheStore.boolean(Key.SUBSCRIPTION_UPDATE_WHEN_CONNECTED_ONLY)
    var subscriptionUserAgent by profileCacheStore.string(Key.SUBSCRIPTION_USER_AGENT)
    var subscriptionAutoUpdate by profileCacheStore.boolean(Key.SUBSCRIPTION_AUTO_UPDATE)
    var subscriptionAutoUpdateDelay by profileCacheStore.stringToInt(Key.SUBSCRIPTION_AUTO_UPDATE_DELAY) { 360 }
    var firstRunDone by configurationStore.boolean(Key.FIRST_RUN_DONE) { false }
    var subscriptionSourceLastSha by configurationStore.string("subscriptionSourceLastSha") {
        "7f0ff73fd6197601a26a8416ebcc9375dc8cf3f9"
    }
    var subscriptionSourcePendingSha by configurationStore.string("subscriptionSourcePendingSha") { "" }
    var subscriptionSourceLastCheckAt by configurationStore.long("subscriptionSourceLastCheckAt") { 0L }
    var subscriptionSourceUpdateAvailable by configurationStore.boolean("subscriptionSourceUpdateAvailable") { false }

    @Volatile
    var firstRunSilentUpdateActive = false

    var rulesFirstCreate by profileCacheStore.boolean("rulesFirstCreate")

    fun getSmartPreferredProxy(groupId: Long): Long {
        return configurationStore.getLong("smartPreferred.$groupId", 0L)
    }

    fun setSmartPreferredProxy(groupId: Long, proxyId: Long) {
        configurationStore.putLong("smartPreferred.$groupId", proxyId)
    }

    fun getSmartPreferredOrder(groupId: Long): List<Long> {
        val raw = configurationStore.getString("smartPreferredOrder.$groupId", "") ?: ""
        if (raw.isBlank()) return emptyList()
        return raw.split(",")
            .mapNotNull { it.trim().toLongOrNull() }
    }

    fun setSmartPreferredOrder(groupId: Long, proxyIds: List<Long>) {
        val raw = proxyIds.joinToString(",")
        configurationStore.putString("smartPreferredOrder.$groupId", raw)
    }

    private fun scopeKey(scope: String): String {
        val normalized = scope.trim().ifBlank { "default" }
        return normalized.hashCode().toUInt().toString(16)
    }

    fun getSmartPreferredProxyScoped(scope: String, groupId: Long): Long {
        return configurationStore.getLong("smartPreferredScope.${scopeKey(scope)}.$groupId", 0L)
    }

    fun setSmartPreferredProxyScoped(scope: String, groupId: Long, proxyId: Long) {
        configurationStore.putLong("smartPreferredScope.${scopeKey(scope)}.$groupId", proxyId)
    }

    private fun transportClassKey(raw: String): String {
        return when (raw.lowercase()) {
            "tls" -> "tls"
            "plain" -> "plain"
            else -> "mixed"
        }
    }

    fun getSmartTransportPenalty(scope: String, groupId: Long, transportClass: String): Int {
        val key = "smartTransportPenalty.${scopeKey(scope)}.$groupId.${transportClassKey(transportClass)}"
        return configurationStore.getInt(key, 0).coerceAtLeast(0)
    }

    fun adjustSmartTransportPenalty(scope: String, groupId: Long, transportClass: String, delta: Int) {
        val normalized = transportClassKey(transportClass)
        val key = "smartTransportPenalty.${scopeKey(scope)}.$groupId.$normalized"
        val ceil = smartTransportPenaltyCeil.coerceIn(500, 5000)
        val current = configurationStore.getInt(key, 0).coerceAtLeast(0)
        configurationStore.putInt(key, (current + delta).coerceIn(0, ceil))
    }

    fun decaySmartTransportPenalty(scope: String, groupId: Long, transportClass: String, amount: Int) {
        adjustSmartTransportPenalty(scope, groupId, transportClass, -amount.coerceAtLeast(0))
    }

    private val smartPreferredOrderDirty = mutableSetOf<Long>()

    fun markSmartPreferredOrderDirty(groupId: Long) {
        synchronized(smartPreferredOrderDirty) {
            smartPreferredOrderDirty.add(groupId)
        }
    }

    fun clearSmartPreferredOrderDirty(groupId: Long) {
        synchronized(smartPreferredOrderDirty) {
            smartPreferredOrderDirty.remove(groupId)
        }
    }

    fun isSmartPreferredOrderDirty(groupId: Long): Boolean {
        return synchronized(smartPreferredOrderDirty) {
            smartPreferredOrderDirty.contains(groupId)
        }
    }

    fun getAutoDnsServers(groupId: Long): List<String> {
        val raw = configurationStore.getString("autoDns.$groupId", "") ?: ""
        if (raw.isBlank()) return emptyList()
        return raw.split(",").mapNotNull { it.trim().takeIf { s -> s.isNotBlank() } }
    }

    fun setAutoDnsServers(groupId: Long, servers: List<String>) {
        val raw = servers.joinToString(",")
        configurationStore.putString("autoDns.$groupId", raw)
    }

    fun getSmartHealthPenalty(profileId: Long): Int {
        return configurationStore.getInt("smartHealthPenalty.$profileId", 0).coerceAtLeast(0)
    }

    fun setSmartHealthPenalty(profileId: Long, penalty: Int) {
        configurationStore.putInt("smartHealthPenalty.$profileId", penalty.coerceIn(0, 2000))
    }

    fun getSmartFailureStreak(profileId: Long): Int {
        return configurationStore.getInt("smartFailureStreak.$profileId", 0).coerceAtLeast(0)
    }

    fun setSmartFailureStreak(profileId: Long, streak: Int) {
        configurationStore.putInt("smartFailureStreak.$profileId", streak.coerceIn(0, 20))
    }

    fun getSmartLastScore(profileId: Long): Int {
        return configurationStore.getInt("smartLastScore.$profileId", -1)
    }

    fun setSmartLastScore(profileId: Long, score: Int) {
        configurationStore.putInt("smartLastScore.$profileId", score.coerceIn(-1, 20000))
    }

    fun getSmartLastBandwidthKbps(profileId: Long): Int {
        return configurationStore.getInt("smartLastBandwidthKbps.$profileId", -1)
    }

    fun setSmartLastBandwidthKbps(profileId: Long, kbps: Int) {
        configurationStore.putInt("smartLastBandwidthKbps.$profileId", kbps.coerceIn(-1, 5_000_000))
    }

    fun getSmartLastObservedAt(profileId: Long): Long {
        return configurationStore.getLong("smartLastObservedAt.$profileId", 0L).coerceAtLeast(0L)
    }

    fun setSmartLastObservedAt(profileId: Long, timestamp: Long) {
        configurationStore.putLong("smartLastObservedAt.$profileId", timestamp.coerceAtLeast(0L))
    }

    fun getSmartLastFailureReason(profileId: Long): String {
        return configurationStore.getString("smartLastFailureReason.$profileId", "") ?: ""
    }

    fun setSmartLastFailureReason(profileId: Long, reason: String) {
        configurationStore.putString("smartLastFailureReason.$profileId", reason.take(80))
    }

    fun getSmartRecentSwitchCount(profileId: Long): Int {
        return configurationStore.getInt("smartRecentSwitchCount.$profileId", 0).coerceAtLeast(0)
    }

    fun setSmartRecentSwitchCount(profileId: Long, count: Int) {
        configurationStore.putInt("smartRecentSwitchCount.$profileId", count.coerceIn(0, 1000))
    }

    fun bumpSmartRecentSwitchCount(profileId: Long) {
        setSmartRecentSwitchCount(profileId, getSmartRecentSwitchCount(profileId) + 1)
    }

    fun decaySmartRecentSwitchCount(profileId: Long, amount: Int = 1) {
        setSmartRecentSwitchCount(profileId, (getSmartRecentSwitchCount(profileId) - amount.coerceAtLeast(0)).coerceAtLeast(0))
    }

    fun normalizedSmartProfilePreset(): String {
        return when (smartProfilePreset.trim().lowercase()) {
            "gaming", "game", "minrtt", "latency" -> "gaming"
            "streaming", "stream", "video", "stable" -> "streaming"
            "download", "leastload", "throughput", "max_download" -> "download"
            "manual" -> "manual"
            else -> "balanced"
        }
    }

    fun smartAdaptivePolicy(): SmartAdaptivePolicy {
        return SmartAdaptivePolicy(
            cooldownSec = smartSwitchCooldownSec,
            minDwellSec = smartSwitchMinDwellSec,
            probeIntervalSec = smartSwitchProbeIntervalSec,
            badProbeIntervalSec = smartSwitchBadProbeIntervalSec,
            warmupRounds = smartSwitchWarmupRounds,
            candidateWins = smartSwitchCandidateWins,
            candidateWinsWarmup = smartSwitchCandidateWinsWarmup,
            minImproveAbs = smartSwitchMinImproveAbs,
            minImprovePct = smartSwitchMinImprovePct,
            weakScore = smartSwitchWeakScore,
            criticalScore = smartSwitchCriticalScore,
            failStreakTrigger = smartSwitchFailStreakTrigger,
            stableLockSec = smartSwitchStableLockSec,
            excellentScore = smartSwitchExcellentScore,
            minThroughputGainPct = smartSwitchMinThroughputGainPct,
            disruptionHoldMinSec = smartDisruptionHoldMinSec,
            disruptionHoldMaxSec = smartDisruptionHoldMaxSec,
        )
    }

    fun applySmartAdaptivePolicy(policy: SmartAdaptivePolicy) {
        smartSwitchCooldownSec = policy.cooldownSec.coerceIn(30, 900)
        smartSwitchMinDwellSec = policy.minDwellSec.coerceIn(30, 1200)
        smartSwitchProbeIntervalSec = policy.probeIntervalSec.coerceIn(10, 120)
        smartSwitchBadProbeIntervalSec = policy.badProbeIntervalSec.coerceIn(5, 60)
        smartSwitchWarmupRounds = policy.warmupRounds.coerceIn(1, 8)
        smartSwitchCandidateWins = policy.candidateWins.coerceIn(2, 10)
        smartSwitchCandidateWinsWarmup = policy.candidateWinsWarmup.coerceIn(1, 5)
        smartSwitchMinImproveAbs = policy.minImproveAbs.coerceIn(80, 1200)
        smartSwitchMinImprovePct = policy.minImprovePct.coerceIn(8, 60)
        smartSwitchWeakScore = policy.weakScore.coerceIn(600, 3000)
        smartSwitchCriticalScore = policy.criticalScore.coerceIn(800, 5000)
        smartSwitchFailStreakTrigger = policy.failStreakTrigger.coerceIn(1, 10)
        smartSwitchStableLockSec = policy.stableLockSec.coerceIn(120, 3600)
        smartSwitchExcellentScore = policy.excellentScore.coerceIn(450, 1400)
        smartSwitchMinThroughputGainPct = policy.minThroughputGainPct.coerceIn(5, 80)
        smartDisruptionHoldMinSec = policy.disruptionHoldMinSec.coerceIn(30, 900)
        smartDisruptionHoldMaxSec = policy.disruptionHoldMaxSec.coerceIn(60, 1800)
    }

    fun applySmartProfilePreset(preset: String) {
        smartProfilePreset = preset
        when (preset) {
            "gaming" -> {
                parallelConcurrency = 24
                connectionTestConcurrent = 24
                smartSwitchCooldownSec = 45
                smartSwitchMinDwellSec = 45
                smartSwitchProbeIntervalSec = 16
                smartSwitchBadProbeIntervalSec = 5
                smartSwitchCandidateWins = 2
                smartSwitchCandidateWinsWarmup = 1
                smartSwitchMinImproveAbs = 140
                smartSwitchMinImprovePct = 12
                smartSwitchStableLockSec = 300
                smartSwitchExcellentScore = 620
                smartSwitchMinThroughputGainPct = 28
            }
            "streaming", "stable" -> {
                smartSwitchCooldownSec = 180
                smartSwitchMinDwellSec = 240
                smartSwitchProbeIntervalSec = 45
                smartSwitchBadProbeIntervalSec = 12
                smartSwitchCandidateWins = 5
                smartSwitchCandidateWinsWarmup = 3
                smartSwitchMinImproveAbs = 320
                smartSwitchMinImprovePct = 24
                smartSwitchStableLockSec = 1200
                smartSwitchExcellentScore = 820
                smartSwitchMinThroughputGainPct = 24
            }
            "download", "max_download" -> {
                parallelConcurrency = 28
                connectionTestConcurrent = 24
                smartSwitchCooldownSec = 90
                smartSwitchMinDwellSec = 90
                smartSwitchProbeIntervalSec = 22
                smartSwitchBadProbeIntervalSec = 8
                smartSwitchCandidateWins = 3
                smartSwitchCandidateWinsWarmup = 2
                smartSwitchMinImproveAbs = 180
                smartSwitchMinImprovePct = 14
                smartSwitchStableLockSec = 600
                smartSwitchExcellentScore = 680
                smartSwitchMinThroughputGainPct = 10
            }
            "manual" -> {
                smartSwitchCooldownSec = 300
                smartSwitchMinDwellSec = 600
                smartSwitchProbeIntervalSec = 60
                smartSwitchBadProbeIntervalSec = 20
                smartSwitchCandidateWins = 5
                smartSwitchCandidateWinsWarmup = 3
                smartSwitchMinImproveAbs = 400
                smartSwitchMinImprovePct = 30
                smartSwitchStableLockSec = 1800
                smartSwitchExcellentScore = 900
                smartSwitchMinThroughputGainPct = 30
            }
            else -> {
                smartSwitchCooldownSec = 120
                smartSwitchMinDwellSec = 150
                smartSwitchProbeIntervalSec = 30
                smartSwitchBadProbeIntervalSec = 10
                smartSwitchCandidateWins = 4
                smartSwitchCandidateWinsWarmup = 2
                smartSwitchMinImproveAbs = 260
                smartSwitchMinImprovePct = 20
                smartSwitchStableLockSec = 900
                smartSwitchExcellentScore = 760
                smartSwitchMinThroughputGainPct = 18
            }
        }
    }

    fun getSmartSuccessCount(profileId: Long): Int {
        return configurationStore.getInt("smartSuccessCount.$profileId", 0).coerceAtLeast(0)
    }

    fun setSmartSuccessCount(profileId: Long, count: Int) {
        configurationStore.putInt("smartSuccessCount.$profileId", count.coerceIn(0, 1_000_000))
    }

    fun getSmartFailureCount(profileId: Long): Int {
        return configurationStore.getInt("smartFailureCount.$profileId", 0).coerceAtLeast(0)
    }

    fun setSmartFailureCount(profileId: Long, count: Int) {
        configurationStore.putInt("smartFailureCount.$profileId", count.coerceIn(0, 1_000_000))
    }

    fun getSmartLastSuccessAt(profileId: Long): Long {
        return configurationStore.getLong("smartLastSuccessAt.$profileId", 0L).coerceAtLeast(0L)
    }

    fun setSmartLastSuccessAt(profileId: Long, timestamp: Long) {
        configurationStore.putLong("smartLastSuccessAt.$profileId", timestamp.coerceAtLeast(0L))
    }

    fun getSmartLastFailureAt(profileId: Long): Long {
        return configurationStore.getLong("smartLastFailureAt.$profileId", 0L).coerceAtLeast(0L)
    }

    fun setSmartLastFailureAt(profileId: Long, timestamp: Long) {
        configurationStore.putLong("smartLastFailureAt.$profileId", timestamp.coerceAtLeast(0L))
    }

    fun getSmartQuarantineUntil(profileId: Long): Long {
        return configurationStore.getLong("smartQuarantineUntil.$profileId", 0L).coerceAtLeast(0L)
    }

    fun setSmartQuarantineUntil(profileId: Long, timestamp: Long) {
        configurationStore.putLong("smartQuarantineUntil.$profileId", timestamp.coerceAtLeast(0L))
    }

    fun clearSmartQuarantine(profileId: Long) {
        setSmartQuarantineUntil(profileId, 0L)
    }

    fun isSmartQuarantined(profileId: Long, now: Long = System.currentTimeMillis()): Boolean {
        if (!smartQuarantineEnabled) return false
        return getSmartQuarantineUntil(profileId) > now
    }

    fun quarantineSmartProfile(profileId: Long, minutes: Int) {
        if (!smartQuarantineEnabled) return
        val durationMs = minutes.coerceIn(1, 24 * 60) * 60_000L
        setSmartQuarantineUntil(profileId, System.currentTimeMillis() + durationMs)
    }

    fun getSmartQualityScore(profileId: Long): Int {
        val latency = getSmartLastScore(profileId)
        val bandwidth = getSmartLastBandwidthKbps(profileId)
        val success = getSmartSuccessCount(profileId)
        val failure = getSmartFailureCount(profileId)
        val streak = getSmartFailureStreak(profileId)
        val penalty = getSmartHealthPenalty(profileId)
        val recentSwitches = getSmartRecentSwitchCount(profileId)
        val observedAt = getSmartLastObservedAt(profileId)
        val successRatio = if (success + failure > 0) {
            success.toDouble() / (success + failure).toDouble()
        } else {
            0.5
        }
        val latencyPart = when {
            latency in 1..180 -> 35
            latency in 181..350 -> 28
            latency in 351..700 -> 20
            latency in 701..1200 -> 10
            else -> 0
        }
        val bandwidthPart = when {
            bandwidth >= 30_000 -> 30
            bandwidth >= 16_000 -> 24
            bandwidth >= 8_000 -> 16
            bandwidth >= 3_000 -> 8
            else -> 0
        }
        val reliabilityPart = (successRatio * 35.0).toInt()
        val penaltyPart = (penalty / 90 + streak * 4 + recentSwitches * 2).coerceAtMost(55)
        val recencyBonus = when {
            observedAt <= 0L -> 0
            System.currentTimeMillis() - observedAt <= 5 * 60_000L -> 6
            System.currentTimeMillis() - observedAt <= 30 * 60_000L -> 3
            else -> 0
        }
        return (latencyPart + bandwidthPart + reliabilityPart + recencyBonus - penaltyPart).coerceIn(0, 100)
    }

    override fun onPreferenceDataStoreChanged(store: PreferenceDataStore, key: String) {
    }
}
