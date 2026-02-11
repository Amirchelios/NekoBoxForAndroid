package moe.matsuri.nb4a.converter

import io.nekohasekai.sagernet.ktx.toStringPretty
import moe.matsuri.nb4a.utils.JavaUtil.gson
import moe.matsuri.nb4a.utils.Util
import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Locale

object ProxyToSingboxConverter {

    private val supportedProtocols = listOf(
        "vmess://",
        "vless://",
        "trojan://",
        "hysteria2://",
        "hy2://",
        "ss://"
    )

    fun convertToSingBoxJson(input: String): String? {
        extractSingBoxJson(input)?.let { return it }
        val configs = extractStandardConfigs(input)
        if (configs.isEmpty()) return null

        val outbounds = mutableListOf<Map<String, Any?>>()
        val validTags = mutableListOf<String>()
        val usedTags = LinkedHashSet<String>()
        val flagCounters = HashMap<String, Int>()

        configs.forEach { config ->
            val outbound = when {
                config.startsWith("vmess://") -> convertVmess(config, usedTags, flagCounters)
                config.startsWith("vless://") -> convertVless(config, usedTags, flagCounters)
                config.startsWith("trojan://") -> convertTrojan(config, usedTags, flagCounters)
                config.startsWith("hysteria2://") || config.startsWith("hy2://") ->
                    convertHysteria2(config, usedTags, flagCounters)
                config.startsWith("ss://") -> convertShadowsocks(config, usedTags, flagCounters)
                else -> null
            }
            if (outbound != null) {
                outbounds.add(outbound)
                outbound["tag"]?.toString()?.let { validTags.add(it) }
            }
        }

        if (outbounds.isEmpty()) return null

        val config = mutableMapOf<String, Any?>()
        config["log"] = mapOf("level" to "warn")
        config["outbounds"] = buildOutbounds(outbounds, validTags)
        return gson.toJson(config)
    }

    private fun extractSingBoxJson(input: String): String? {
        tryParseSingBoxJson(input)?.let { return it }
        if (isBase64(input)) {
            decodeBase64(input)?.let { decoded ->
                tryParseSingBoxJson(decoded)?.let { return it }
            }
        }
        if (isDataUriBase64(input)) {
            decodeDataUri(input)?.let { decoded ->
                tryParseSingBoxJson(decoded)?.let { return it }
            }
        }
        return null
    }

    private fun tryParseSingBoxJson(raw: String): String? {
        val trimmed = raw.trim()
        if (!trimmed.startsWith("{")) return null
        return runCatching {
            val json = JSONObject(trimmed)
            val hasOutbounds = json.optJSONArray("outbounds") != null
            val hasInbounds = json.optJSONArray("inbounds") != null
            if (!hasOutbounds && !hasInbounds) return@runCatching null
            if (hasOutbounds && !hasValidOutboundTypes(json)) return@runCatching null
            json.toString()
        }.getOrNull()
    }

    private fun hasValidOutboundTypes(json: JSONObject): Boolean {
        val outbounds = json.optJSONArray("outbounds") ?: return true
        val typeRegex = Regex("^[a-z0-9_\\-]+$")
        for (i in 0 until outbounds.length()) {
            val outbound = outbounds.opt(i) as? JSONObject ?: return false
            val type = outbound.optString("type").trim()
            if (type.isBlank() || !typeRegex.matches(type)) return false
        }
        return true
    }

    private fun buildOutbounds(
        outbounds: List<Map<String, Any?>>,
        validTags: List<String>
    ): List<Map<String, Any?>> {
        val list = mutableListOf<Map<String, Any?>>()
        list.add(
            mapOf(
                "type" to "selector",
                "tag" to "proxy",
                "outbounds" to (listOf("auto_parallel", "auto") + validTags + "direct")
            )
        )
        list.add(mapOf("type" to "direct", "tag" to "direct"))
        list.add(
            mapOf(
                "type" to "parallel",
                "tag" to "auto_parallel",
                "outbounds" to validTags,
                "strategy" to "race",
                "concurrency" to 12,
                "delay" to "250ms",
                "timeout" to "5000ms"
            )
        )
        list.add(
            mapOf(
                "type" to "urltest",
                "tag" to "auto",
                "outbounds" to validTags,
                "url" to "https://cp.cloudflare.com/generate_204",
                "interrupt_exist_connections" to false,
                "interval" to "15s",
                "tolerance" to 80
            )
        )
        list.addAll(outbounds)
        return list
    }

    private fun extractStandardConfigs(input: String): List<String> {
        val configs = mutableListOf<String>()
        val lines = input.split('\n').map { it.trim() }.filter { it.isNotEmpty() }

        lines.forEach { line ->
            when {
                isBase64(line) -> decodeBase64(line)?.let { configs.addAll(extractConfigsFromText(it)) }
                isDataUriBase64(line) -> decodeDataUri(line)?.let { configs.addAll(extractConfigsFromText(it)) }
                else -> configs.addAll(extractConfigsFromText(line))
            }
        }

        val allText = input.replace("\n", " ")
        configs.addAll(extractConfigsFromText(allText))
        return configs.distinct()
    }

    private fun extractConfigsFromText(text: String): List<String> {
        val configs = mutableListOf<String>()
        supportedProtocols.forEach { protocol ->
            val regex = Regex("(${Regex.escape(protocol)}[^\\s]+)")
            regex.findAll(text).forEach { match ->
                configs.add(match.value)
            }
        }
        return configs
    }

    private fun convertVmess(
        input: String,
        usedTags: MutableSet<String>,
        flagCounters: MutableMap<String, Int>
    ): Map<String, Any?>? {
        return try {
            val payload = input.removePrefix("vmess://")
            val decoded = String(Util.b64Decode(payload))
            val json = JSONObject(decoded)
            val server = json.optString("add")
            val port = json.optString("port").toIntOrNull() ?: return null
            val uuid = json.optString("id")
            if (server.isBlank() || uuid.isBlank()) return null
            val displayName = json.optString("ps").trim()
            val tag = buildTag(displayName, "vmess", usedTags, flagCounters)

            val transport = mutableMapOf<String, Any?>()
            if (json.optString("net") == "ws") {
                transport["type"] = "ws"
                transport["path"] = json.optString("path", "/")
                val host = json.optString("host", server)
                transport["headers"] = mapOf("Host" to host)
            }

            val tls = mutableMapOf<String, Any?>("enabled" to false)
            if (json.optString("tls") == "tls") {
                tls["enabled"] = true
                tls["server_name"] = json.optString("sni", server)
                tls["insecure"] = false
                tls["alpn"] = listOf("http/1.1")
                tls["utls"] = mapOf("enabled" to true, "fingerprint" to "chrome")
            }

            val allowedSecurity = setOf(
                "auto",
                "none",
                "zero",
                "aes-128-gcm",
                "chacha20-poly1305",
                "aes-128-ctr"
            )
            val security = json.optString("scy", "auto").lowercase(Locale.US).trim()

            mapOf(
                "type" to "vmess",
                "tag" to tag,
                "server" to server,
                "server_port" to port,
                "uuid" to uuid,
                "security" to (if (security in allowedSecurity) security else "auto"),
                "alter_id" to (json.optString("aid", "0").toIntOrNull() ?: 0),
                "transport" to transport,
                "tls" to tls
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun convertVless(
        input: String,
        usedTags: MutableSet<String>,
        flagCounters: MutableMap<String, Int>
    ): Map<String, Any?>? {
        return try {
            val uri = URI(input)
            val server = uri.host ?: return null
            val port = if (uri.port > 0) uri.port else 443
            val uuid = uri.userInfo ?: return null
            val params = parseQuery(uri.rawQuery)
            val displayName = uri.rawFragment?.let {
                URLDecoder.decode(it, StandardCharsets.UTF_8.name())
            }?.trim().orEmpty()
            val tag = buildTag(displayName, "vless", usedTags, flagCounters)

            val transport = mutableMapOf<String, Any?>()
            if (params["type"] == "ws") {
                transport["type"] = "ws"
                transport["path"] = params["path"] ?: "/"
                val host = params["host"] ?: server
                transport["headers"] = mapOf("Host" to host)
            }

            val tls = mutableMapOf<String, Any?>("enabled" to false)
            val security = params["security"]
            val tlsEnabled = security == "tls" || security == "reality" ||
                port in listOf(443, 2053, 2083, 2087, 2096, 8443)
            if (tlsEnabled) {
                tls["enabled"] = true
                tls["server_name"] = params["sni"] ?: server
                tls["insecure"] = false
                tls["alpn"] = listOf("http/1.1")
                tls["utls"] = mapOf("enabled" to true, "fingerprint" to (params["fp"] ?: "chrome"))
                if (security == "reality") {
                    val reality = mutableMapOf<String, Any?>("enabled" to true)
                    params["pbk"]?.let { reality["public_key"] = it }
                    params["sid"]?.let { reality["short_id"] = it }
                    tls["reality"] = reality
                }
            }

            mapOf(
                "type" to "vless",
                "tag" to tag,
                "server" to server,
                "server_port" to port,
                "uuid" to uuid,
                "flow" to (params["flow"] ?: ""),
                "transport" to transport,
                "tls" to tls
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun convertTrojan(
        input: String,
        usedTags: MutableSet<String>,
        flagCounters: MutableMap<String, Int>
    ): Map<String, Any?>? {
        return try {
            val uri = URI(input)
            val server = uri.host ?: return null
            val port = if (uri.port > 0) uri.port else 443
            val password = uri.userInfo ?: return null
            val params = parseQuery(uri.rawQuery)
            val displayName = uri.rawFragment?.let {
                URLDecoder.decode(it, StandardCharsets.UTF_8.name())
            }?.trim().orEmpty()
            val tag = buildTag(displayName, "trojan", usedTags, flagCounters)

            val transport = mutableMapOf<String, Any?>()
            if (params["type"] == "ws") {
                transport["type"] = "ws"
                transport["path"] = params["path"] ?: "/"
                val host = params["host"] ?: server
                transport["headers"] = mapOf("Host" to host)
            }

            val tls = mapOf(
                "enabled" to true,
                "server_name" to (params["sni"] ?: server),
                "insecure" to false,
                "alpn" to listOf("http/1.1"),
                "utls" to mapOf("enabled" to true, "fingerprint" to "chrome")
            )

            mapOf(
                "type" to "trojan",
                "tag" to tag,
                "server" to server,
                "server_port" to port,
                "password" to password,
                "transport" to transport,
                "tls" to tls
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun convertHysteria2(
        input: String,
        usedTags: MutableSet<String>,
        flagCounters: MutableMap<String, Int>
    ): Map<String, Any?>? {
        return try {
            val uri = URI(input)
            val server = uri.host ?: return null
            val port = uri.port.takeIf { it > 0 } ?: return null
            val params = parseQuery(uri.rawQuery)
            val password = uri.userInfo ?: params["password"].orEmpty()
            val displayName = uri.rawFragment?.let {
                URLDecoder.decode(it, StandardCharsets.UTF_8.name())
            }?.trim().orEmpty()
            val tag = buildTag(displayName, "hysteria2", usedTags, flagCounters)

            mapOf(
                "type" to "hysteria2",
                "tag" to tag,
                "server" to server,
                "server_port" to port,
                "password" to password,
                "tls" to mapOf(
                    "enabled" to true,
                    "server_name" to (params["sni"] ?: server),
                    "insecure" to true
                )
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun convertShadowsocks(
        input: String,
        usedTags: MutableSet<String>,
        flagCounters: MutableMap<String, Int>
    ): Map<String, Any?>? {
        return try {
            val uri = URI(input)
            val server = uri.host ?: return null
            val port = uri.port.takeIf { it > 0 } ?: return null
            val rawUserInfo = uri.rawUserInfo ?: return null
            val decodedUserInfo = runCatching { String(Util.b64Decode(rawUserInfo)) }.getOrNull()
            val parts = when {
                decodedUserInfo != null && decodedUserInfo.contains(":") -> decodedUserInfo.split(":")
                rawUserInfo.contains(":") -> rawUserInfo.split(":").map {
                    URLDecoder.decode(it, StandardCharsets.UTF_8.name())
                }
                else -> return null
            }
            if (parts.size < 2) return null
            val method = parts[0]
            val password = parts.subList(1, parts.size).joinToString(":")
            val methodRegex = Regex("^[a-z0-9_\\-]+$", RegexOption.IGNORE_CASE)
            if (method.isBlank() || password.isBlank() || !methodRegex.matches(method)) return null
            val displayName = uri.rawFragment?.let {
                URLDecoder.decode(it, StandardCharsets.UTF_8.name())
            }?.trim().orEmpty()
            val tag = buildTag(displayName, "ss", usedTags, flagCounters)

            mapOf(
                "type" to "shadowsocks",
                "tag" to tag,
                "server" to server,
                "server_port" to port,
                "method" to method,
                "password" to password
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun buildTag(
        preferred: String,
        prefix: String,
        usedTags: MutableSet<String>,
        flagCounters: MutableMap<String, Int>
    ): String {
        val rawName = if (preferred.isBlank()) "" else preferred
        val (flag, remainder) = extractFlagAndRemainder(rawName)
        val base = if (flag.isNotBlank()) {
            val next = (flagCounters[flag] ?: 0) + 1
            flagCounters[flag] = next
            val label = if (remainder.isBlank()) "" else " $remainder"
            sanitizeTag("$flag $next$label")
        } else {
            generateTag(prefix)
        }
        var candidate = base
        var counter = 2
        while (!usedTags.add(candidate)) {
            candidate = "$base ($counter)"
            counter++
        }
        return candidate
    }

    private fun sanitizeTag(raw: String): String {
        val trimmed = raw.trim().replace("\n", " ").replace("\r", " ")
        return if (trimmed.isBlank()) "proxy" else trimmed
    }

    private fun generateTag(prefix: String): String {
        val random = java.util.UUID.randomUUID().toString().take(8)
        return "${prefix.lowercase(Locale.US)}-$random"
    }

    private fun extractFlagAndRemainder(input: String): Pair<String, String> {
        var i = 0
        var flagStart = -1
        var flagEnd = -1
        while (i < input.length) {
            val cp1 = Character.codePointAt(input, i)
            val c1Len = Character.charCount(cp1)
            if (isRegionalIndicator(cp1)) {
                val nextIndex = i + c1Len
                if (nextIndex < input.length) {
                    val cp2 = Character.codePointAt(input, nextIndex)
                    if (isRegionalIndicator(cp2)) {
                        flagStart = i
                        flagEnd = nextIndex + Character.charCount(cp2)
                        break
                    }
                }
            }
            i += c1Len
        }
        if (flagStart < 0) return "" to input.trim()
        val flag = input.substring(flagStart, flagEnd)
        val remainder = buildString {
            var idx = 0
            while (idx < input.length) {
                val cp = Character.codePointAt(input, idx)
                val len = Character.charCount(cp)
                if (!isRegionalIndicator(cp)) {
                    append(input, idx, idx + len)
                }
                idx += len
            }
        }.replace(flag, "").trim()
        return flag to remainder
    }

    private fun isRegionalIndicator(codePoint: Int): Boolean {
        return codePoint in 0x1F1E6..0x1F1FF
    }

    private fun isBase64(str: String): Boolean {
        if (str.isEmpty() || str.length % 4 != 0) return false
        return str.matches(Regex("^[A-Za-z0-9+/=]+$"))
    }

    private fun isDataUriBase64(str: String): Boolean {
        return str.startsWith("data:") && str.contains("base64,")
    }

    private fun decodeDataUri(str: String): String? {
        val base64Part = str.substringAfter("base64,", "")
        if (base64Part.isBlank()) return null
        return decodeBase64(base64Part)
    }

    private fun decodeBase64(str: String): String? {
        return runCatching { String(Util.b64Decode(str.trim())) }.getOrNull()
    }

    private fun parseQuery(query: String?): Map<String, String> {
        if (query.isNullOrBlank()) return emptyMap()
        return query.split("&").mapNotNull { part ->
            val idx = part.indexOf("=")
            if (idx <= 0) return@mapNotNull null
            val key = URLDecoder.decode(part.substring(0, idx), StandardCharsets.UTF_8.name())
            val value = URLDecoder.decode(part.substring(idx + 1), StandardCharsets.UTF_8.name())
            key to value
        }.toMap()
    }
}
