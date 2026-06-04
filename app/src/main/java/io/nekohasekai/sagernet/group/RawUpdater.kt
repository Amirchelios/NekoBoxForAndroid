package io.nekohasekai.sagernet.group

import android.annotation.SuppressLint
import io.nekohasekai.sagernet.DEFAULT_SUBSCRIPTION_SOURCES
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.*
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.http.HttpBean
import io.nekohasekai.sagernet.fmt.hysteria.HysteriaBean
import io.nekohasekai.sagernet.fmt.hysteria.parseHysteriaJsonLike
import io.nekohasekai.sagernet.fmt.hysteria.parseHysteria1Json
import io.nekohasekai.sagernet.fmt.mieru.MieruBean
import io.nekohasekai.sagernet.fmt.naive.NaiveBean
import io.nekohasekai.sagernet.fmt.shadowsocks.ShadowsocksBean
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean
import io.nekohasekai.sagernet.fmt.ssh.SSHBean
import io.nekohasekai.sagernet.fmt.trojan.TrojanBean
import io.nekohasekai.sagernet.fmt.trojan_go.TrojanGoBean
import io.nekohasekai.sagernet.fmt.trojan_go.parseTrojanGo
import io.nekohasekai.sagernet.fmt.tuic.TuicBean
import io.nekohasekai.sagernet.fmt.v2ray.StandardV2RayBean
import io.nekohasekai.sagernet.fmt.v2ray.VMessBean
import io.nekohasekai.sagernet.fmt.v2ray.isTLS
import io.nekohasekai.sagernet.fmt.v2ray.setTLS
import io.nekohasekai.sagernet.fmt.wireguard.WireGuardBean
import io.nekohasekai.sagernet.ktx.*
import libcore.Libcore
import moe.matsuri.nb4a.Protocols
import moe.matsuri.nb4a.converter.ProxyToSingboxConverter
import moe.matsuri.nb4a.proxy.anytls.AnyTLSBean
import moe.matsuri.nb4a.proxy.config.ConfigBean
import moe.matsuri.nb4a.utils.Util
import org.ini4j.Ini
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import org.yaml.snakeyaml.TypeDescription
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.error.YAMLException
import java.io.StringReader
import androidx.core.net.toUri
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope

@Suppress("EXPERIMENTAL_API_USAGE")
object RawUpdater : GroupUpdater() {
    private const val SMART_HEAD_COMPARE_COUNT = 3

    @SuppressLint("Recycle")
    override suspend fun doUpdate(
        proxyGroup: ProxyGroup,
        subscription: SubscriptionBean,
        userInterface: GroupManager.Interface?,
        byUser: Boolean
    ) {

        val link = subscription.link
        var rawText = ""
        var proxies: List<AbstractBean>
        var aggregateConfig = ""
        if (link.startsWith("content://")) {
            rawText = app.contentResolver.openInputStream(link.toUri())
                ?.bufferedReader()
                ?.readText()
                .orEmpty()

            proxies = rawText.let { parseRaw(it) }
                ?: error(app.getString(R.string.no_proxies_found_in_subscription))
        } else {

            val response = buildSubscriptionRequest(
                subscription.link,
                subscription.customUserAgent.takeIf { it.isNotBlank() } ?: USER_AGENT
            ).execute()
            rawText = Util.getStringBox(response.contentString)
            val defaultSources = if (GroupManager.isDefaultSubscriptionGroup(proxyGroup)) {
                fetchDefaultSubscriptionTexts(
                    subscription.customUserAgent.takeIf { it.isNotBlank() } ?: USER_AGENT,
                    rawText
                )
            } else {
                listOf(rawText)
            }
            val directProxies = defaultSources.flatMap { parseRaw(it).orEmpty() }
            val subscriptionLinks = defaultSources.flatMap { extractSubscriptionLinks(it) }.distinct()
            val nestedProxies = mutableListOf<AbstractBean>()
            val nestedTexts = mutableListOf<String>()
            if (subscriptionLinks.isNotEmpty()) {
                val userAgent = subscription.customUserAgent.takeIf { it.isNotBlank() } ?: USER_AGENT
                val batches = coroutineScope {
                    subscriptionLinks.map { subLink ->
                        async {
                            val subText = runCatching {
                                Util.getStringBox(
                                    buildSubscriptionRequest(subLink, userAgent)
                                        .execute().contentString
                                )
                            }.getOrDefault("")
                            if (subText.isBlank()) return@async Pair("", emptyList<AbstractBean>())
                            val parsed = runCatching { parseRaw(subText).orEmpty() }.getOrElse { emptyList() }
                            Pair(subText, parsed)
                        }
                    }.awaitAll()
                }
                for ((subText, subProxies) in batches) {
                    if (subText.isBlank()) continue
                    nestedTexts.add(subText)
                    nestedProxies.addAll(subProxies)
                }
            }

            val allParsedProxies = directProxies + nestedProxies
            if (allParsedProxies.isNotEmpty()) {
                proxies = dedupeDefaultGroupProxies(proxyGroup, allParsedProxies)
                val aggregateTexts = defaultSources + nestedTexts
                rawText = aggregateTexts.joinToString("\n")
                aggregateConfig = sanitizeAggregateConfig(buildAggregateConfig(aggregateTexts))
            } else {
                aggregateConfig = sanitizeAggregateConfig(
                    ProxyToSingboxConverter.convertToSingBoxJson(rawText).orEmpty()
                )
                if (aggregateConfig.isBlank()) {
                    error(app.getString(R.string.no_proxies_found))
                }
                proxies = emptyList()
            }

            subscription.subscriptionUserinfo =
                Util.getStringBox(response.getHeader("Subscription-Userinfo"))

            // 修改默认名字
            if (proxyGroup.name?.startsWith("Subscription #") == true) {
                var remoteName = Util.getStringBox(response.getHeader("content-disposition"))
                if (remoteName.isNotBlank()) {
                    remoteName = Util.decodeFilename(remoteName)
                    if (remoteName.isNotBlank()) {
                        proxyGroup.name = remoteName
                    }
                }
            }
        }

        val aggregateName = app.getString(R.string.menu_auto_select)
        if (aggregateConfig.isBlank()) {
            aggregateConfig = sanitizeAggregateConfig(
                ProxyToSingboxConverter.convertToSingBoxJson(rawText).orEmpty()
            )
        }
        if (proxies.none { it is ConfigBean && it.type == 0 }) {
            val aggregate = ConfigBean().apply {
                applyDefaultValues()
                type = 0
                config = aggregateConfig
                name = aggregateName
            }
            proxies = listOf(aggregate) + proxies
        }

        val proxiesMap = LinkedHashMap<String, AbstractBean>()
        val proxyNameCounters = HashMap<String, Int>()
        // normalize any embedded sing-box configs to avoid invalid vmess security fields
        proxies.forEach {
            if (it is ConfigBean && it.type == 0 && it.config.isNotBlank()) {
                it.config = sanitizeSingBoxConfig(it.config)
            }
        }
        for (proxy in proxies) {
            val name = proxy.displayName()
            val count = (proxyNameCounters[name] ?: 0) + 1
            proxyNameCounters[name] = count
            val key = if (count == 1) name else "$name#$count"
            proxiesMap[key] = proxy
        }
        proxies = proxiesMap.values.toList()

        if (subscription.forceResolve) forceResolve(proxies, proxyGroup.id)

        val exists = SagerDatabase.proxyDao.getByGroup(proxyGroup.id)
        val duplicate = ArrayList<String>()
        if (subscription.deduplication) {
            Logs.d("Before deduplication: ${proxies.size}")
            if (GroupManager.isDefaultSubscriptionGroup(proxyGroup)) {
                val unique = LinkedHashMap<String, AbstractBean>()
                for (_proxy in proxies) {
                    val fingerprint = proxyFingerprint(_proxy)
                    if (unique.containsKey(fingerprint)) {
                        duplicate.add(_proxy.displayName())
                    } else {
                        unique[fingerprint] = _proxy
                    }
                }
                proxies = unique.values.toList()
            } else {
                val uniqueProxies = LinkedHashSet<Protocols.Deduplication>()
                val uniqueNames = HashMap<Protocols.Deduplication, String>()
                for (_proxy in proxies) {
                    val proxy = Protocols.Deduplication(_proxy, _proxy.javaClass.toString())
                    if (!uniqueProxies.add(proxy)) {
                        val index = uniqueProxies.indexOf(proxy)
                        if (uniqueNames.containsKey(proxy)) {
                            val name = uniqueNames[proxy]!!.replace(" ($index)", "")
                            if (name.isNotBlank()) {
                                duplicate.add("$name ($index)")
                                uniqueNames[proxy] = ""
                            }
                        }
                        duplicate.add(_proxy.displayName() + " ($index)")
                    } else {
                        uniqueNames[proxy] = _proxy.displayName()
                    }
                }
                uniqueProxies.retainAll(uniqueNames.keys)
                proxies = uniqueProxies.toList().map { it.bean }
            }
        }

        Logs.d("New profiles: ${proxies.size}")

        fun buildIndexedNameMap(list: List<AbstractBean>): Map<String, AbstractBean> {
            val map = LinkedHashMap<String, AbstractBean>()
            val counters = HashMap<String, Int>()
            for (bean in list) {
                val name = bean.displayName()
                val count = (counters[name] ?: 0) + 1
                counters[name] = count
                val key = if (count == 1) name else "$name#$count"
                map[key] = bean
            }
            return map
        }

        fun buildIndexedEntityMap(list: List<ProxyEntity>): Map<String, ProxyEntity> {
            val map = LinkedHashMap<String, ProxyEntity>()
            val counters = HashMap<String, Int>()
            for (entity in list) {
                val name = entity.displayName()
                val count = (counters[name] ?: 0) + 1
                counters[name] = count
                val key = if (count == 1) name else "$name#$count"
                map[key] = entity
            }
            return map
        }

        val nameMap = buildIndexedNameMap(proxies)

        Logs.d("Unique profiles: ${nameMap.size}")

        if (shouldSkipSmartHeadUpdate(
                proxyGroup,
                nameMap.values.toList(),
                aggregateName,
                exists
            )
        ) {
            subscription.lastUpdated = (System.currentTimeMillis() / 1000).toInt()
            SagerDatabase.groupDao.updateGroup(proxyGroup)
            finishUpdate(proxyGroup)
            userInterface?.onUpdateSuccess(
                proxyGroup, 0, emptyList(), emptyMap(), emptyList(), emptyList(), byUser
            )
            return
        }

        val toDelete = ArrayList<ProxyEntity>()
        val existMap = buildIndexedEntityMap(exists)
        val toReplace = existMap.mapNotNull { (key, entity) ->
            if (nameMap.containsKey(key)) key to entity else let {
                toDelete.add(entity)
                null
            }
        }.toMap()

        val protectedDelete = toDelete.filter { GroupManager.isRemovalBlocked(proxyGroup, it) }
        if (protectedDelete.isNotEmpty()) {
            toDelete.removeAll(protectedDelete)
        }

        Logs.d("toDelete profiles: ${toDelete.size}")
        Logs.d("toReplace profiles: ${toReplace.size}")

        val toUpdate = ArrayList<ProxyEntity>()
        val added = mutableListOf<String>()
        val updated = mutableMapOf<String, String>()
        val deleted = toDelete.map { it.displayName() }

        fun isAggregate(bean: AbstractBean): Boolean {
            return bean is ConfigBean && bean.type == 0 &&
                (bean.name == "sing-box config (all)" || bean.name == aggregateName)
        }

        var userOrder = 1L
        var changed = toDelete.size
        for ((name, bean) in nameMap.entries) {
            val desiredOrder = if (isAggregate(bean)) 0L else userOrder
            if (toReplace.contains(name)) {
                val entity = toReplace[name]!!
                val existsBean = entity.requireBean()
                existsBean.applyFeatureSettings(bean)
                when {
                    existsBean != bean -> {
                        changed++
                        entity.putBean(bean)
                        toUpdate.add(entity)
                        updated[entity.displayName()] = name

                        Logs.d("Updated profile: $name")
                    }

                    entity.userOrder != desiredOrder -> {
                        entity.putBean(bean)
                        toUpdate.add(entity)
                        entity.userOrder = desiredOrder

                        Logs.d("Reordered profile: $name")
                    }

                    else -> {
                        Logs.d("Ignored profile: $name")
                    }
                }
            } else {
                changed++
                SagerDatabase.proxyDao.addProxy(
                    ProxyEntity(
                        groupId = proxyGroup.id, userOrder = desiredOrder
                    ).apply {
                        putBean(bean)
                    })
                added.add(name)
                Logs.d("Inserted profile: $name")
            }
            if (!isAggregate(bean)) {
                userOrder++
            }
        }

        SagerDatabase.proxyDao.updateProxy(toUpdate).also {
            Logs.d("Updated profiles: $it")
        }

        SagerDatabase.proxyDao.deleteProxy(toDelete).also {
            Logs.d("Deleted profiles: $it")
        }

        val existCount = SagerDatabase.proxyDao.countByGroup(proxyGroup.id).toInt()

        if (existCount != proxies.size) {
            Logs.e("Exist profiles: $existCount, new profiles: ${proxies.size}")
        }

        subscription.lastUpdated = (System.currentTimeMillis() / 1000).toInt()
        SagerDatabase.groupDao.updateGroup(proxyGroup)
        finishUpdate(proxyGroup)

        userInterface?.onUpdateSuccess(
            proxyGroup, changed, added, updated, deleted, duplicate, byUser
        )
    }

    private fun shouldSkipSmartHeadUpdate(
        proxyGroup: ProxyGroup,
        newProxies: List<AbstractBean>,
        aggregateName: String,
        existing: List<ProxyEntity>
    ): Boolean {
        if (!isSmartHeadCompareEnabled(proxyGroup)) return false
        if (GroupUpdater.isForceUpdate(proxyGroup.id)) return false
        if (shouldSkipCountMismatchUpdate(proxyGroup, newProxies, aggregateName, existing)) return false
        val newFiltered = filterProxiesForCompare(newProxies, aggregateName)
        if (newFiltered.isEmpty()) return false
        val oldFiltered = filterExistingForCompare(existing, aggregateName)
        if (oldFiltered.isEmpty()) return false
        val count = SMART_HEAD_COMPARE_COUNT.coerceAtMost(
            minOf(newFiltered.size, oldFiltered.size)
        )
        if (count <= 0) return false
        val newHead = newFiltered.take(count).map { it.toString() }
        val oldHead = oldFiltered.take(count).map { it.toString() }
        return newHead == oldHead
    }

    private fun shouldSkipCountMismatchUpdate(
        proxyGroup: ProxyGroup,
        newProxies: List<AbstractBean>,
        aggregateName: String,
        existing: List<ProxyEntity>
    ): Boolean {
        if (!isSmartHeadCompareEnabled(proxyGroup)) return true
        if (GroupUpdater.isForceUpdate(proxyGroup.id)) return true
        val newCount = filterProxiesForCompare(newProxies, aggregateName).size
        val oldCount = filterExistingForCompare(existing, aggregateName).size
        return newCount != oldCount
    }

    private fun isSmartHeadCompareEnabled(group: ProxyGroup): Boolean {
        return GroupManager.isDefaultSubscriptionGroup(group)
    }

    private fun filterProxiesForCompare(
        proxies: List<AbstractBean>,
        aggregateName: String
    ): List<AbstractBean> {
        return proxies.filterNot { bean ->
            if (bean !is ConfigBean || bean.type != 0) return@filterNot false
            bean.name == aggregateName || bean.name == "sing-box config (all)"
        }
    }

    private fun filterExistingForCompare(
        proxies: List<ProxyEntity>,
        aggregateName: String
    ): List<AbstractBean> {
        return proxies
            .sortedWith(compareBy<ProxyEntity> { it.userOrder }.thenBy { it.id })
            .mapNotNull { proxy ->
                when {
                    GroupManager.isDefaultAutoSelectConfig(proxy) -> null
                    GroupManager.isAutoSelectAggregate(proxy) -> null
                    else -> runCatching { proxy.requireBean() }.getOrNull()
                }
            }
            .filterNot { bean ->
                if (bean !is ConfigBean || bean.type != 0) return@filterNot false
                bean.name == aggregateName || bean.name == "sing-box config (all)"
            }
    }

    @Suppress("UNCHECKED_CAST")
    suspend fun parseRaw(text: String, fileName: String = ""): List<AbstractBean>? {

        val proxies = mutableListOf<AbstractBean>()

        if (text.contains("proxies:")) {

            // clash & meta

            try {

                val yaml = Yaml().apply {
                    addTypeDescription(TypeDescription(String::class.java, "str"))
                }.loadAs(text, Map::class.java)

                val globalClientFingerprint = yaml["global-client-fingerprint"]?.toString() ?: ""

                for (proxy in (yaml["proxies"] as? (List<Map<String, Any?>>) ?: error(
                    app.getString(R.string.no_proxies_found_in_file)
                ))) {
                    // Note: YAML numbers parsed as "Long"

                    when (proxy["type"] as String) {
                        "socks5" -> {
                            proxies.add(SOCKSBean().apply {
                                serverAddress = proxy["server"] as String
                                serverPort = proxy["port"].toString().toInt()
                                username = proxy["username"]?.toString()
                                password = proxy["password"]?.toString()
                                name = proxy["name"]?.toString()
                            })
                        }

                        "http" -> {
                            proxies.add(HttpBean().apply {
                                serverAddress = proxy["server"] as String
                                serverPort = proxy["port"].toString().toInt()
                                username = proxy["username"]?.toString()
                                password = proxy["password"]?.toString()
                                setTLS(proxy["tls"]?.toString() == "true")
                                sni = proxy["sni"]?.toString()
                                name = proxy["name"]?.toString()
                                allowInsecure = proxy["skip-cert-verify"]?.toString() == "true"
                            })
                        }

                        "vmess", "vless", "trojan" -> {
                            val bean = when (proxy["type"] as String) {
                                "vmess" -> VMessBean()
                                "vless" -> VMessBean().apply {
                                    alterId = -1 // make it VLESS
                                    packetEncoding = 2 // clash meta default XUDP
                                }

                                "trojan" -> TrojanBean().apply {
                                    security = "tls"
                                }

                                else -> error("impossible")
                            }

                            bean.serverAddress = proxy["server"]?.toString() ?: continue
                            bean.serverPort = proxy["port"]?.toString()?.toIntOrNull() ?: continue

                            for (opt in proxy) {
                                when (opt.key) {
                                    "name" -> bean.name = opt.value?.toString()
                                    "password" -> if (bean is TrojanBean) bean.password =
                                        opt.value?.toString()

                                    "uuid" -> if (bean is VMessBean) bean.uuid =
                                        opt.value?.toString()

                                    "alterId" -> if (bean is VMessBean && !bean.isVLESS) bean.alterId =
                                        opt.value?.toString()?.toIntOrNull()

                                    "cipher" -> if (bean is VMessBean && !bean.isVLESS) bean.encryption =
                                        (opt.value as? String)

                                    "flow" -> if (bean is VMessBean && bean.isVLESS) {
                                        (opt.value as? String)?.let {
                                            if (it.contains("xtls-rprx-vision")) {
                                                bean.encryption = "xtls-rprx-vision"
                                            }
                                        }
                                    }

                                    "packet-encoding" -> if (bean is VMessBean) {
                                        bean.packetEncoding = when ((opt.value as? String)) {
                                            "packetaddr" -> 1
                                            "xudp" -> 2
                                            else -> 0
                                        }
                                    }

                                    "tls" -> if (bean is VMessBean) {
                                        bean.security =
                                            if (opt.value as? Boolean == true) "tls" else ""
                                    }

                                    "servername", "sni" -> bean.sni = opt.value?.toString()

                                    "alpn" -> bean.alpn =
                                        (opt.value as? List<Any>)?.joinToString("\n")

                                    "skip-cert-verify" -> bean.allowInsecure =
                                        opt.value as? Boolean == true

                                    "client-fingerprint" -> bean.utlsFingerprint =
                                        opt.value as String

                                    "reality-opts" -> (opt.value as? Map<String, Any?>)?.also {
                                        for (realityOpt in it) {
                                            bean.security = "tls"

                                            when (realityOpt.key) {
                                                "public-key" -> bean.realityPubKey =
                                                    realityOpt.value?.toString()

                                                "short-id" -> bean.realityShortId =
                                                    realityOpt.value?.toString()
                                            }
                                        }
                                    }

                                    "network" -> {
                                        when (opt.value) {
                                            "h2", "http" -> bean.type = "http"
                                            "ws", "grpc" -> bean.type = opt.value as String
                                        }
                                    }

                                    "ws-opts" -> (opt.value as? Map<String, Any?>)?.also {
                                        for (wsOpt in it) {
                                            when (wsOpt.key) {
                                                "headers" -> (wsOpt.value as? Map<Any, Any?>)?.forEach { (key, value) ->
                                                    when (key.toString().lowercase()) {
                                                        "host" -> {
                                                            bean.host = value?.toString()
                                                        }
                                                    }
                                                }

                                                "path" -> {
                                                    bean.path = wsOpt.value?.toString()
                                                }

                                                "max-early-data" -> {
                                                    bean.wsMaxEarlyData =
                                                        wsOpt.value?.toString()?.toIntOrNull()
                                                }

                                                "early-data-header-name" -> {
                                                    bean.earlyDataHeaderName =
                                                        wsOpt.value?.toString()
                                                }

                                                "v2ray-http-upgrade" -> {
                                                    if (wsOpt.value as? Boolean == true) {
                                                        bean.type = "httpupgrade"
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    "h2-opts" -> (opt.value as? Map<String, Any?>)?.also {
                                        for (h2Opt in it) {
                                            when (h2Opt.key) {
                                                "host" -> bean.host =
                                                    (h2Opt.value as? List<Any>)?.joinToString("\n")

                                                "path" -> bean.path = h2Opt.value?.toString()
                                            }
                                        }
                                    }

                                    "http-opts" -> (opt.value as? Map<String, Any?>)?.also {
                                        for (httpOpt in it) {
                                            when (httpOpt.key) {
                                                "path" -> bean.path =
                                                    (httpOpt.value as? List<Any>)?.joinToString("\n")

                                                "headers" -> {
                                                    (httpOpt.value as? Map<Any, List<Any>>)?.forEach { (key, value) ->
                                                        when (key.toString().lowercase()) {
                                                            "host" -> {
                                                                bean.host = value.joinToString("\n")
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    "grpc-opts" -> (opt.value as? Map<String, Any?>)?.also {
                                        for (grpcOpt in it) {
                                            when (grpcOpt.key) {
                                                "grpc-service-name" -> bean.path =
                                                    grpcOpt.value?.toString()
                                            }
                                        }
                                    }

                                    "smux" -> (opt.value as? Map<String, Any?>)?.also {
                                        for (smuxOpt in it) {
                                            when (smuxOpt.key) {
                                                "enabled" -> bean.enableMux =
                                                    smuxOpt.value.toString() == "true"

                                                "max-streams" -> bean.muxConcurrency =
                                                    smuxOpt.value.toString().toInt()

                                                "padding" -> bean.muxPadding =
                                                    smuxOpt.value.toString() == "true"
                                            }
                                        }
                                    }
                                }
                            }
                            proxies.add(bean)
                        }

                        "anytls" -> {
                            val bean = AnyTLSBean()
                            for (opt in proxy) {
                                if (opt.value == null) continue
                                when (opt.key.replace("_", "-")) {
                                    "name" -> bean.name = opt.value.toString()
                                    "server" -> bean.serverAddress = opt.value as String
                                    "port" -> bean.serverPort = opt.value.toString().toInt()
                                    "password" -> bean.password = opt.value.toString()
                                    "client-fingerprint" -> bean.utlsFingerprint =
                                        opt.value as String

                                    "sni" -> bean.sni = opt.value.toString()
                                    "skip-cert-verify" -> bean.allowInsecure =
                                        opt.value.toString() == "true"

                                    "alpn" -> {
                                        val alpn = (opt.value as? (List<String>))
                                        bean.alpn = alpn?.joinToString("\n")
                                    }
                                }
                            }
                            proxies.add(bean)
                        }

                        "hysteria" -> {
                            val bean = HysteriaBean()
                            bean.protocolVersion = 1
                            var hopPorts = ""
                            for (opt in proxy) {
                                if (opt.value == null) continue
                                when (opt.key.replace("_", "-")) {
                                    "name" -> bean.name = opt.value.toString()
                                    "server" -> bean.serverAddress = opt.value as String
                                    "port" -> bean.serverPorts = opt.value.toString()
                                    "ports" -> hopPorts = opt.value.toString()

                                    "obfs" -> bean.obfuscation = opt.value.toString()

                                    "auth-str" -> {
                                        bean.authPayloadType = HysteriaBean.TYPE_STRING
                                        bean.authPayload = opt.value.toString()
                                    }

                                    "sni" -> bean.sni = opt.value.toString()

                                    "skip-cert-verify" -> bean.allowInsecure =
                                        opt.value.toString() == "true"

                                    "up" -> bean.uploadMbps =
                                        opt.value.toString().substringBefore(" ").toIntOrNull()
                                            ?: 100

                                    "down" -> bean.downloadMbps =
                                        opt.value.toString().substringBefore(" ").toIntOrNull()
                                            ?: 100

                                    "recv-window-conn" -> bean.connectionReceiveWindow =
                                        opt.value.toString().toIntOrNull() ?: 0

                                    "recv-window" -> bean.streamReceiveWindow =
                                        opt.value.toString().toIntOrNull() ?: 0

                                    "disable-mtu-discovery" -> bean.disableMtuDiscovery =
                                        opt.value.toString() == "true" || opt.value.toString() == "1"

                                    "alpn" -> {
                                        val alpn = (opt.value as? (List<String>))
                                        bean.alpn = alpn?.joinToString("\n") ?: "h3"
                                    }
                                }
                            }
                            if (hopPorts.isNotBlank()) {
                                bean.serverPorts = hopPorts
                            }
                            proxies.add(bean)
                        }

                        "hysteria2" -> {
                            proxies.add(
                                proxy
                                    .entries
                                    .associate { it.key.replace("_", "-") to it.value }
                                    .parseHysteriaJsonLike()
                            )
                        }

                        "tuic" -> {
                            val bean = TuicBean()
                            var ip = ""
                            for (opt in proxy) {
                                if (opt.value == null) continue
                                when (opt.key.replace("_", "-")) {
                                    "name" -> bean.name = opt.value.toString()
                                    "server" -> bean.serverAddress = opt.value.toString()
                                    "ip" -> ip = opt.value.toString()
                                    "port" -> bean.serverPort = opt.value.toString().toInt()

                                    "token" -> {
                                        bean.protocolVersion = 4
                                        bean.token = opt.value.toString()
                                    }

                                    "uuid" -> bean.uuid = opt.value.toString()

                                    "password" -> bean.token = opt.value.toString()

                                    "skip-cert-verify" -> bean.allowInsecure =
                                        opt.value.toString() == "true"

                                    "disable-sni" -> bean.disableSNI =
                                        opt.value.toString() == "true"

                                    "reduce-rtt" -> bean.reduceRTT =
                                        opt.value.toString() == "true"

                                    "sni" -> bean.sni = opt.value.toString()

                                    "alpn" -> {
                                        val alpn = (opt.value as? (List<String>))
                                        bean.alpn = alpn?.joinToString("\n")
                                    }

                                    "congestion-controller" -> bean.congestionController =
                                        opt.value.toString()

                                    "udp-relay-mode" -> bean.udpRelayMode = opt.value.toString()

                                }
                            }
                            if (ip.isNotBlank()) {
                                bean.serverAddress = ip
                                if (bean.sni.isNullOrBlank() && !bean.serverAddress.isNullOrBlank() && !bean.serverAddress.isIpAddress()) {
                                    bean.sni = bean.serverAddress
                                }
                            }
                            proxies.add(bean)
                        }
                    }
                }

                // Fix ent
                proxies.forEach {
                    it.initializeDefaultValues()
                    if (it is StandardV2RayBean) {
                        // 1. SNI
                        if (it.isTLS() && it.sni.isNullOrBlank() && !it.host.isNullOrBlank() && !it.host.isIpAddress()) {
                            it.sni = it.host
                        }
                        // 2. globalClientFingerprint
                        if (!it.realityPubKey.isNullOrBlank() && it.utlsFingerprint.isNullOrBlank()) {
                            it.utlsFingerprint = globalClientFingerprint
                            if (it.utlsFingerprint.isNullOrBlank()) it.utlsFingerprint = "chrome"
                        }
                    }
                }
                return proxies
            } catch (e: YAMLException) {
                Logs.w(e)
            }
        } else if (text.contains("[Interface]")) {
            // wireguard
            try {
                proxies.addAll(parseWireGuard(text).map {
                    if (fileName.isNotBlank()) it.name = fileName.removeSuffix(".conf")
                    it
                })
                return proxies
            } catch (e: Exception) {
                Logs.w(e)
            }
        }

        try {
            val json = JSONTokener(text).nextValue()
            return parseJSON(json)
        } catch (ignored: Exception) {
        }

        try {
            return parseProxies(text.decodeBase64UrlSafe()).takeIf { it.isNotEmpty() }
                ?: error("Not found")
        } catch (e: Exception) {
            Logs.w(e)
        }

        try {
            return parseProxies(text).takeIf { it.isNotEmpty() } ?: error("Not found")
        } catch (e: SubscriptionFoundException) {
            throw e
        } catch (ignored: Exception) {
        }

        return null
    }

    fun clashCipher(cipher: String): String {
        return when (cipher) {
            "dummy" -> "none"
            else -> cipher
        }
    }

    internal fun sanitizeAggregateConfig(config: String): String {
        if (config.isBlank()) return config
        return runCatching {
            val root = JSONObject(config)
            fixVmessSecurity(root)
            sanitizeOutbounds(root)
            root.toString()
        }.getOrDefault(config)
    }

    fun buildAggregateConfigForRaw(rawText: String): String {
        return sanitizeAggregateConfig(
            ProxyToSingboxConverter.convertToSingBoxJson(rawText).orEmpty()
        )
    }

    private fun sanitizeSingBoxConfig(config: String): String {
        if (config.isBlank()) return config
        return runCatching {
            val root = JSONObject(config)
            fixVmessSecurity(root)
            removeParallelOutbounds(root)
            sanitizeOutbounds(root)
            root.toString()
        }.getOrDefault(config)
    }

    private fun fixVmessSecurity(value: Any?) {
        when (value) {
            is JSONObject -> {
                val type = value.optString("type")
                if (type == "vmess") {
                    val sec = value.opt("security")
                    val secStr = sec?.toString()?.trim()
                    val allowed = setOf("auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305", "aes-128-ctr")
                    if (sec == JSONObject.NULL || sec == null || secStr.isNullOrBlank() || secStr == "null" || secStr !in allowed) {
                        value.put("security", "auto")
                    }
                }
                val keys = value.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    fixVmessSecurity(value.opt(k))
                }
            }
            is JSONArray -> {
                for (i in 0 until value.length()) {
                    fixVmessSecurity(value.opt(i))
                }
            }
        }
    }

    private fun sanitizeOutbounds(root: JSONObject) {
        val outbounds = root.optJSONArray("outbounds") ?: return
        val invalidTags = HashSet<String>()
        val newOutbounds = JSONArray()
        for (i in 0 until outbounds.length()) {
            val outbound = outbounds.optJSONObject(i) ?: continue
            val type = outbound.optString("type")
            if (!isValidOutboundType(type)) {
                outbound.optString("tag").takeIf { it.isNotBlank() }?.let { invalidTags.add(it) }
                continue
            }
            if (type == "vmess") {
                val sec = outbound.opt("security")
                if (sec == JSONObject.NULL || (sec is String && sec.isBlank())) {
                    outbound.put("security", "auto")
                }
            }
            if (type == "vless") {
                normalizeVlessOutbound(outbound)
            }
            if (type == "urltest") {
                outbound.remove("timeout")
                outbound.remove("timeoout")
                outbound.put("interrupt_exist_connections", false)
            }
            if (isInvalidRealityOutbound(outbound)) {
                outbound.optString("tag").takeIf { it.isNotBlank() }?.let { invalidTags.add(it) }
                continue
            }
            newOutbounds.put(outbound)
        }
        if (invalidTags.isNotEmpty()) {
            for (i in 0 until newOutbounds.length()) {
                val outbound = newOutbounds.optJSONObject(i) ?: continue
                val type = outbound.optString("type")
                if (type == "selector" || type == "urltest" || type == "parallel") {
                    val list = outbound.optJSONArray("outbounds") ?: continue
                    val filtered = JSONArray()
                    for (j in 0 until list.length()) {
                        val tag = list.optString(j)
                        if (!invalidTags.contains(tag)) {
                            filtered.put(tag)
                        }
                    }
                    if (filtered.length() == 0 && type == "urltest") {
                        // urltest with no candidates causes sing-box parser failure; degrade to direct selector
                        outbound.put("type", "selector")
                        filtered.put("direct")
                    }
                    outbound.put("outbounds", filtered)
                    if (outbound.optString("type") == "selector") {
                        fixSelectorDefault(outbound, filtered)
                    }
                }
            }
        }
        root.put("outbounds", newOutbounds)
    }

    private fun isValidOutboundType(type: String?): Boolean {
        val normalized = type?.trim().orEmpty()
        if (normalized.isBlank()) return false
        return Regex("^[a-z0-9_\\-]+$").matches(normalized)
    }

    private fun normalizeVlessOutbound(outbound: JSONObject) {
        val flow = outbound.optString("flow", "").trim().removeSuffix("-udp443")
        if (flow == "xtls-rprx-vision") {
            outbound.put("flow", flow)
        } else {
            outbound.remove("flow")
        }
        val transport = outbound.optJSONObject("transport") ?: return
        when (transport.optString("type").trim()) {
            "raw", "none", "tcp" -> outbound.remove("transport")
        }
    }

    private fun removeParallelOutbounds(root: JSONObject) {
        val outbounds = root.optJSONArray("outbounds") ?: return
        val removedTags = HashSet<String>()
        val newOutbounds = JSONArray()
        for (i in 0 until outbounds.length()) {
            val outbound = outbounds.optJSONObject(i) ?: continue
            val type = outbound.optString("type")
            val tag = outbound.optString("tag")
            if (type == "parallel" || isInternalParallelTag(tag)) {
                if (tag.isNotBlank()) removedTags.add(tag)
                continue
            }
            newOutbounds.put(outbound)
        }
        if (removedTags.isNotEmpty()) {
            for (i in 0 until newOutbounds.length()) {
                val outbound = newOutbounds.optJSONObject(i) ?: continue
                val type = outbound.optString("type")
                if (type == "selector" || type == "urltest") {
                    val list = outbound.optJSONArray("outbounds") ?: continue
                    val filtered = JSONArray()
                    for (j in 0 until list.length()) {
                        val tag = list.optString(j)
                        if (!isInternalParallelTag(tag) && !removedTags.contains(tag)) {
                            filtered.put(tag)
                        }
                    }
                    if (filtered.length() == 0 && type == "urltest") {
                        // urltest with no candidates causes sing-box parser failure; degrade to direct selector
                        outbound.put("type", "selector")
                        filtered.put("direct")
                    }
                    outbound.put("outbounds", filtered)
                    if (outbound.optString("type") == "selector") {
                        fixSelectorDefault(outbound, filtered)
                    }
                }
            }
        }
        root.put("outbounds", newOutbounds)
    }

    private fun isInternalParallelTag(tag: String): Boolean {
        return tag == "auto_parallel" || tag == "bond_min_rtt" ||
            tag == "bond_download" || tag == "bond_race"
    }

    private fun fixSelectorDefault(selector: JSONObject, outbounds: JSONArray) {
        val defaultTag = selector.optString("default")
        if (defaultTag.isBlank()) return
        var exists = false
        for (i in 0 until outbounds.length()) {
            if (outbounds.optString(i) == defaultTag) {
                exists = true
                break
            }
        }
        if (exists) return
        if (outbounds.length() > 0) {
            selector.put("default", outbounds.optString(0))
        } else {
            selector.remove("default")
        }
    }

    private fun isInvalidRealityOutbound(outbound: JSONObject): Boolean {
        val tls = outbound.optJSONObject("tls") ?: return false
        val reality = tls.optJSONObject("reality") ?: return false
        if (!reality.optBoolean("enabled", false)) return false
        val key = reality.optString("public_key", "").trim()
        return key.isBlank() || !key.matches(Regex("^[A-Za-z0-9_-]{43,64}$"))
    }

    private fun buildSubscriptionRequest(url: String, userAgent: String) =
        Libcore.newHttpClient().apply {
            trySocks5(DataStore.mixedPort)
            tryH3Direct()
            when (DataStore.appTLSVersion) {
                "1.3" -> restrictedTLS()
            }
        }.newRequest().apply {
            if (DataStore.allowInsecureOnRequest) {
                allowInsecure()
            }
            setURL(url)
            setUserAgent(userAgent)
        }

    private suspend fun fetchDefaultSubscriptionTexts(
        userAgent: String,
        alreadyFetchedDefault: String
    ): List<String> = coroutineScope {
        val remaining = DEFAULT_SUBSCRIPTION_SOURCES.drop(1)
        val extraTexts = remaining.map { subLink ->
            async {
                runCatching {
                    Util.getStringBox(
                        buildSubscriptionRequest(subLink, userAgent)
                            .execute().contentString
                    )
                }.getOrDefault("")
            }
        }.awaitAll().filter { it.isNotBlank() }
        listOf(alreadyFetchedDefault) + extraTexts
    }

    private fun extractSubscriptionLinks(rawText: String): List<String> {
        val texts = mutableListOf(rawText)
        runCatching { rawText.decodeBase64UrlSafe() }
            .getOrNull()
            ?.takeIf { it.isNotBlank() && it != rawText }
            ?.let { texts.add(it) }

        return texts.asSequence()
            .flatMap { it.lineSequence() }
            .map { it.trim() }
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .filter { it.startsWith("http://") || it.startsWith("https://") }
            .distinct()
            .toList()
    }

    private fun dedupeDefaultGroupProxies(
        proxyGroup: ProxyGroup,
        proxies: List<AbstractBean>
    ): List<AbstractBean> {
        if (!GroupManager.isDefaultSubscriptionGroup(proxyGroup)) return proxies
        val seen = HashSet<String>()
        return proxies.filter { bean ->
            seen.add(proxyFingerprint(bean))
        }
    }

    private fun proxyFingerprint(bean: AbstractBean): String {
        fun norm(value: Any?): String = value?.toString()
            ?.trim()
            ?.lowercase()
            .orEmpty()
        fun exact(value: Any?): String = value?.toString()?.trim().orEmpty()
        fun endpoint(portOverride: Any? = null): String {
            return "${norm(bean.serverAddress)}:${portOverride ?: bean.serverPort ?: ""}"
        }
        fun normalizedFlow(value: Any?): String = exact(value).removeSuffix("-udp443")
        val parts = mutableListOf(bean.javaClass.name, endpoint())
        when (bean) {
            is StandardV2RayBean -> {
                parts += listOf(
                    exact(bean.uuid),
                    norm(bean.type),
                    norm(bean.security),
                    norm(bean.sni),
                    exact(bean.alpn),
                    norm(bean.utlsFingerprint),
                    exact(bean.allowInsecure),
                    norm(bean.host),
                    exact(bean.path),
                    normalizedFlow(bean.encryption),
                    exact(bean.realityPubKey),
                    exact(bean.realityShortId),
                    exact(bean.packetEncoding),
                    exact(bean.wsMaxEarlyData),
                    exact(bean.earlyDataHeaderName),
                    exact(bean.enableECH),
                    exact(bean.echConfig),
                )
                if (bean is VMessBean) parts += exact(bean.alterId)
                if (bean is TrojanBean) parts += exact(bean.password)
                if (bean is HttpBean) parts += listOf(exact(bean.username), exact(bean.password))
            }
            is ShadowsocksBean -> parts += listOf(
                norm(bean.method),
                exact(bean.password),
                exact(bean.plugin),
            )
            is SOCKSBean -> parts += listOf(
                exact(bean.protocol),
                exact(bean.username),
                exact(bean.password),
            )
            is HysteriaBean -> {
                parts[1] = endpoint(bean.serverPorts)
                parts += listOf(
                    exact(bean.protocolVersion),
                    exact(bean.authPayload),
                    exact(bean.obfuscation),
                    norm(bean.sni),
                    exact(bean.alpn),
                )
            }
            is TuicBean -> parts += listOf(
                exact(bean.uuid),
                exact(bean.token),
                norm(bean.sni),
                exact(bean.protocolVersion),
                norm(bean.congestionController),
            )
            is TrojanGoBean -> parts += listOf(
                exact(bean.password),
                norm(bean.sni),
                norm(bean.host),
                exact(bean.path),
            )
            is NaiveBean -> parts += listOf(
                exact(bean.username),
                exact(bean.password),
                norm(bean.sni),
            )
            is MieruBean -> parts += listOf(
                exact(bean.username),
                exact(bean.password),
                exact(bean.protocol),
            )
            is SSHBean -> parts += listOf(
                exact(bean.username),
                exact(bean.authType),
                exact(bean.password),
                exact(bean.privateKey),
                exact(bean.publicKey),
            )
            is WireGuardBean -> parts += listOf(
                exact(bean.localAddress),
                exact(bean.privateKey),
                exact(bean.peerPublicKey),
                exact(bean.peerPreSharedKey),
            )
            is AnyTLSBean -> parts += listOf(
                exact(bean.password),
                norm(bean.sni),
            )
            else -> parts += exact(bean.displayAddress())
        }
        return parts.joinToString("|")
    }

    private fun buildAggregateConfig(rawTexts: List<String>): String {
        if (rawTexts.isEmpty()) return ""
        val outbounds = JSONArray()
        val validTags = ArrayList<String>()
        val usedTags = HashSet<String>()
        val parallelIntervalSec = DataStore.parallelIntervalSec.coerceIn(5, 600)
        val parallelTolerance = DataStore.parallelTolerance.coerceIn(10, 300)
        val primaryTag = "auto"
        for (raw in rawTexts) {
            val jsonText = ProxyToSingboxConverter.convertToSingBoxJson(raw).orEmpty()
            if (jsonText.isBlank()) continue
            val root = runCatching { JSONObject(jsonText) }.getOrNull() ?: continue
            val list = root.optJSONArray("outbounds") ?: continue
            for (i in 0 until list.length()) {
                val outbound = list.optJSONObject(i) ?: continue
                val type = outbound.optString("type")
                if (type == "selector" || type == "urltest" || type == "direct" ||
                    type == "block" || type == "dns"
                ) {
                    continue
                }
                var tag = outbound.optString("tag")
                if (tag.isBlank()) continue
                if (usedTags.contains(tag)) {
                    var index = 1
                    var newTag = "$tag-$index"
                    while (usedTags.contains(newTag)) {
                        index++
                        newTag = "$tag-$index"
                    }
                    tag = newTag
                    outbound.put("tag", tag)
                }
                usedTags.add(tag)
                validTags.add(tag)
                outbounds.put(outbound)
            }
        }
        if (validTags.isEmpty()) return ""
        val root = JSONObject()
        root.put("log", JSONObject().put("level", "warn"))
        val merged = JSONArray()
        merged.put(JSONObject().apply {
            put("type", "selector")
            put("tag", "proxy")
            put("default", primaryTag)
            val list = JSONArray()
            list.put("auto")
            validTags.forEach { list.put(it) }
            list.put("direct")
            put("outbounds", list)
        })
        merged.put(JSONObject().apply {
            put("type", "direct")
            put("tag", "direct")
        })
        merged.put(JSONObject().apply {
            put("type", "urltest")
            put("tag", "auto")
            val list = JSONArray()
            validTags.forEach { list.put(it) }
            put("outbounds", list)
            put("url", DataStore.parallelUrl.takeIf { it.isNotBlank() } ?: DataStore.connectionTestURL)
            put("interrupt_exist_connections", false)
            put("interval", "${parallelIntervalSec}s")
            put("tolerance", parallelTolerance)
        })
        for (i in 0 until outbounds.length()) {
            merged.put(outbounds.getJSONObject(i))
        }
        root.put("outbounds", merged)
        return root.toString()
    }

    fun parseWireGuard(conf: String): List<WireGuardBean> {
        val ini = Ini(StringReader(conf))
        val iface = ini["Interface"] ?: error("Missing 'Interface' selection")
        val bean = WireGuardBean().applyDefaultValues()
        val localAddresses = iface.getAll("Address")
        if (localAddresses.isNullOrEmpty()) error("Empty address in 'Interface' selection")
        bean.localAddress = localAddresses.flatMap { it.split(",") }.joinToString("\n")
        bean.privateKey = iface["PrivateKey"]
        bean.mtu = iface["MTU"]?.toIntOrNull()
        val peers = ini.getAll("Peer")
        if (peers.isNullOrEmpty()) error("Missing 'Peer' selections")
        val beans = mutableListOf<WireGuardBean>()
        for (peer in peers) {
            val endpoint = peer["Endpoint"]
            if (endpoint.isNullOrBlank() || !endpoint.contains(":")) {
                continue
            }

            val peerBean = bean.clone()
            peerBean.serverAddress = endpoint.substringBeforeLast(":")
            peerBean.serverPort = endpoint.substringAfterLast(":").toIntOrNull() ?: continue
            peerBean.peerPublicKey = peer["PublicKey"] ?: continue
            peerBean.peerPreSharedKey = peer["PresharedKey"]
            beans.add(peerBean.applyDefaultValues())
        }
        if (beans.isEmpty()) error("Empty available peer list")
        return beans
    }

    fun parseJSON(json: Any): List<AbstractBean> {
        val proxies = ArrayList<AbstractBean>()

        if (json is JSONObject) {
            when {
                json.has("server") && (json.has("up") || json.has("up_mbps")) -> {
                    return listOf(json.parseHysteria1Json())
                }

                json.has("remote_addr") -> {
                    return listOf(json.parseTrojanGo())
                }

                json.has("outbounds") -> {
                    val fullConfig = json.toStringPretty()
                    val aggregate = ConfigBean().apply {
                        applyDefaultValues()
                        type = 0
                        config = fullConfig
                        name = "sing-box config (all)"
                    }
                    val outbounds = json.getJSONArray("outbounds")
                        .filterIsInstance<JSONObject>()
                        .mapNotNull {
                            val ty = it.getStr("type")
                            if (ty == null || ty == "" ||
                                ty == "dns" || ty == "block" || ty == "direct" || ty == "selector" || ty == "urltest" || ty == "parallel"
                                || !isValidOutboundType(ty)
                            ) {
                                null
                            } else {
                                it
                            }
                        }.map {
                            ConfigBean().apply {
                                applyDefaultValues()
                                type = 1
                                config = it.toStringPretty()
                                name = it.getStr("tag")
                            }
                        }
                    return listOf(aggregate) + outbounds
                }

                json.has("server") && json.has("server_port") -> {
                    return listOf(ConfigBean().applyDefaultValues().apply {
                        type = 1
                        config = json.toStringPretty()
                    })
                }
            }
        } else {
            json as JSONArray
            json.forEach { _, it ->
                if (isJsonObjectValid(it)) {
                    proxies.addAll(parseJSON(it))
                }
            }
        }

        proxies.forEach { it.initializeDefaultValues() }
        return proxies
    }

}
