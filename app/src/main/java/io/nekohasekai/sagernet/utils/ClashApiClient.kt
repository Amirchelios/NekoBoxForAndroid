package io.nekohasekai.sagernet.utils

import io.nekohasekai.sagernet.database.DataStore
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

class ClashApiClient(
    private val baseUrl: String = controllerBaseUrl(DataStore.yacdURL),
    private val secret: String = "",
) {
    data class ProxyItem(
        val name: String,
        val type: String,
        val udp: Boolean,
        val historyDelay: Int?,
        val all: List<String>,
        val now: String?,
    ) {
        val isProxyGroup: Boolean
            get() = all.isNotEmpty()

        val isSelectableProxy: Boolean
            get() = type !in NON_PROXY_TYPES && !isProxyGroup
    }

    data class ProxySnapshot(
        val proxies: Map<String, ProxyItem>,
        val groupNames: List<String>,
    ) {
        fun preferredGroupNameFor(proxyName: String): String? {
            val candidates = groupNames.filter { groupName ->
                proxies[groupName]?.all?.contains(proxyName) == true
            }
            if (candidates.isEmpty()) return preferredFallbackGroupName()
            candidates.firstOrNull { it.equals("proxy", ignoreCase = true) }?.let { return it }
            candidates.firstOrNull { proxies[it]?.type in SELECTOR_GROUP_TYPES }?.let { return it }
            return candidates.firstOrNull() ?: preferredFallbackGroupName()
        }

        fun preferredFallbackGroupName(): String? {
            if (groupNames.isEmpty()) return null
            groupNames.firstOrNull { it.equals("proxy", ignoreCase = true) }?.let { return it }
            groupNames.firstOrNull { it == "GLOBAL" }?.let { return it }
            return groupNames.firstOrNull()
        }
    }

    fun isReady(): Boolean {
        return runCatching {
            request("GET", "/version").code in 200..299
        }.getOrDefault(false)
    }

    fun fetchProxies(): ProxySnapshot {
        val response = request("GET", "/proxies")
        if (response.code !in 200..299) {
            error("Clash API /proxies failed: HTTP ${response.code}")
        }
        val root = JSONObject(response.body)
        val proxiesJson = root.optJSONObject("proxies") ?: JSONObject()
        val proxies = linkedMapOf<String, ProxyItem>()
        val groupNames = arrayListOf<String>()

        val keys = proxiesJson.keys()
        while (keys.hasNext()) {
            val name = keys.next()
            val item = proxiesJson.optJSONObject(name) ?: continue
            val all = item.optJSONArray("all")?.let { array ->
                buildList {
                    for (i in 0 until array.length()) {
                        array.optString(i).takeIf { it.isNotBlank() }?.let(::add)
                    }
                }
            }.orEmpty()
            val history = item.optJSONArray("history")
            val lastHistory = history?.optJSONObject(history.length() - 1)
            val proxy = ProxyItem(
                name = item.optString("name", name),
                type = item.optString("type", "Unknown"),
                udp = item.optBoolean("udp", false),
                historyDelay = lastHistory?.optInt("delay")?.takeIf { it > 0 },
                all = all,
                now = item.optString("now").takeIf { it.isNotBlank() },
            )
            proxies[name] = proxy
            if (proxy.isProxyGroup) groupNames.add(name)
        }

        groupNames.sortWith(compareBy<String> { it != "GLOBAL" }.thenBy { it.lowercase() })
        return ProxySnapshot(proxies, groupNames)
    }

    fun switchProxy(groupName: String, proxyName: String): Boolean {
        val body = JSONObject().put("name", proxyName).toString()
        return request("PUT", "/proxies/${encodePathSegment(groupName)}", body).code in 200..299
    }

    private fun request(method: String, path: String, body: String? = null): Response {
        val connection = URL(baseUrl.trimEnd('/') + path).openConnection() as HttpURLConnection
        try {
            connection.connectTimeout = TIMEOUT_MS
            connection.readTimeout = TIMEOUT_MS
            connection.requestMethod = method
            connection.useCaches = false
            if (secret.isNotBlank()) {
                connection.setRequestProperty("Authorization", "Bearer $secret")
            }
            if (body != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val text = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
            return Response(code, text)
        } finally {
            connection.disconnect()
        }
    }

    private data class Response(val code: Int, val body: String)

    private companion object {
        const val TIMEOUT_MS = 1_500

        val NON_PROXY_TYPES = setOf(
            "Direct",
            "Fallback",
            "Reject",
            "Pass",
            "Selector",
            "URLTest",
            "LoadBalance",
            "Unknown",
        )
        val SELECTOR_GROUP_TYPES = setOf("Selector", "URLTest", "Fallback", "LoadBalance")

        fun controllerBaseUrl(yacdUrl: String): String {
            val url = URL(yacdUrl)
            val port = if (url.port >= 0) url.port else url.defaultPort
            return URL(url.protocol, url.host, port, "").toString().trimEnd('/')
        }

        fun encodePathSegment(value: String): String {
            return URLEncoder.encode(value, "UTF-8").replace("+", "%20")
        }
    }
}
