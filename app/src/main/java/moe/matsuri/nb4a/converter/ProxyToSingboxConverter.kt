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
        "hy2://"
    )

    fun convertToSingBoxJson(input: String): String? {
        val configs = extractStandardConfigs(input)
        if (configs.isEmpty()) return null

        val outbounds = mutableListOf<Map<String, Any?>>()
        val validTags = mutableListOf<String>()

        configs.forEach { config ->
            val outbound = when {
                config.startsWith("vmess://") -> convertVmess(config)
                config.startsWith("vless://") -> convertVless(config)
                config.startsWith("trojan://") -> convertTrojan(config)
                config.startsWith("hysteria2://") || config.startsWith("hy2://") -> convertHysteria2(config)
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

    private fun buildOutbounds(
        outbounds: List<Map<String, Any?>>,
        validTags: List<String>
    ): List<Map<String, Any?>> {
        val list = mutableListOf<Map<String, Any?>>()
        list.add(
            mapOf(
                "type" to "selector",
                "tag" to "proxy",
                "outbounds" to (listOf("auto") + validTags + "direct")
            )
        )
        list.add(mapOf("type" to "direct", "tag" to "direct"))
        list.add(
            mapOf(
                "type" to "urltest",
                "tag" to "auto",
                "outbounds" to validTags,
                "url" to "https://www.gstatic.com/generate_204",
                "interrupt_exist_connections" to false,
                "interval" to "30s"
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

    private fun convertVmess(input: String): Map<String, Any?>? {
        return try {
            val payload = input.removePrefix("vmess://")
            val decoded = String(Util.b64Decode(payload))
            val json = JSONObject(decoded)
            val server = json.optString("add")
            val port = json.optString("port").toIntOrNull() ?: return null
            val uuid = json.optString("id")
            if (server.isBlank() || uuid.isBlank()) return null

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

            mapOf(
                "type" to "vmess",
                "tag" to generateTag("vmess"),
                "server" to server,
                "server_port" to port,
                "uuid" to uuid,
                "security" to json.optString("scy", "auto"),
                "alter_id" to (json.optString("aid", "0").toIntOrNull() ?: 0),
                "transport" to transport,
                "tls" to tls
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun convertVless(input: String): Map<String, Any?>? {
        return try {
            val uri = URI(input)
            val server = uri.host ?: return null
            val port = if (uri.port > 0) uri.port else 443
            val uuid = uri.userInfo ?: return null
            val params = parseQuery(uri.rawQuery)

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
                "tag" to generateTag("vless"),
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

    private fun convertTrojan(input: String): Map<String, Any?>? {
        return try {
            val uri = URI(input)
            val server = uri.host ?: return null
            val port = if (uri.port > 0) uri.port else 443
            val password = uri.userInfo ?: return null
            val params = parseQuery(uri.rawQuery)

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
                "tag" to generateTag("trojan"),
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

    private fun convertHysteria2(input: String): Map<String, Any?>? {
        return try {
            val uri = URI(input)
            val server = uri.host ?: return null
            val port = uri.port.takeIf { it > 0 } ?: return null
            val params = parseQuery(uri.rawQuery)
            val password = uri.userInfo ?: params["password"].orEmpty()

            mapOf(
                "type" to "hysteria2",
                "tag" to generateTag("hysteria2"),
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

    private fun convertShadowsocks(input: String): Map<String, Any?>? {
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
            if (method.isBlank() || password.isBlank()) return null

            mapOf(
                "type" to "shadowsocks",
                "tag" to generateTag("ss"),
                "server" to server,
                "server_port" to port,
                "method" to method,
                "password" to password
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun generateTag(prefix: String): String {
        val random = java.util.UUID.randomUUID().toString().take(8)
        return "${prefix.lowercase(Locale.US)}-$random"
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
