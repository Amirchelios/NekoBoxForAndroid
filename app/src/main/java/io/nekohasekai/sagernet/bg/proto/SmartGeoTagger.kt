package io.nekohasekai.sagernet.bg.proto

import io.nekohasekai.sagernet.database.ProfileManager
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.fmt.buildConfig
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import libcore.Libcore
import org.json.JSONObject
import java.net.InetAddress
import java.net.URLEncoder
import java.util.Locale
import kotlin.coroutines.suspendCoroutine
import io.nekohasekai.sagernet.bg.GuardedProcessPool
import io.nekohasekai.sagernet.ktx.tryResume
import io.nekohasekai.sagernet.ktx.tryResumeWithException
import moe.matsuri.nb4a.utils.Util

object SmartGeoTagger {

    private val mutex = Mutex()
    private const val testTimeoutMs = 5000
    private val testLinks = listOf(
        "https://www.instagram.com/",
        "https://www.youtube.com/"
    )

    suspend fun runForGroup(groupId: Long) {
        if (!mutex.tryLock()) return
        try {
            val profiles = SagerDatabase.proxyDao.getByGroup(groupId)
            val toUpdate = mutableListOf<ProxyEntity>()
            val toDelete = mutableListOf<ProxyEntity>()

            for (profile in profiles) {
                if (isAggregateConfig(profile)) continue

                val testResult = runHealthCheck(profile)
                if (testResult == null) {
                    toDelete.add(profile)
                    continue
                }

                val host = resolveServerHost(profile)
                val geo = host?.let { GeoResolver.resolve(it) }
                val country = geo?.country?.ifBlank { "Unknown Country" } ?: "Unknown Country"
                val code = geo?.countryCode?.ifBlank { "" } ?: ""
                val city = geo?.city?.ifBlank { "Unknown City" } ?: "Unknown City"
                val flag = flagFromCountryCode(code)
                val name = "${flag} ${country} - ${city} - ${testResult.latencyMs}ms"

                val bean = profile.requireBean()
                bean.name = name
                profile.putBean(bean)
                toUpdate.add(profile)
            }

            if (toUpdate.isNotEmpty()) {
                ProfileManager.updateProfile(toUpdate)
            }
            for (profile in toDelete) {
                ProfileManager.deleteProfile(profile.groupId, profile.id)
            }
        } catch (e: Exception) {
            Logs.w(e)
        } finally {
            mutex.unlock()
        }
    }

    private fun isAggregateConfig(profile: ProxyEntity): Boolean {
        val bean = profile.configBean ?: return false
        return profile.type == ProxyEntity.TYPE_CONFIG && bean.type == 0
    }

    private suspend fun runHealthCheck(profile: ProxyEntity): HealthResult? {
        val tester = MultiUrlTest(profile, testLinks, testTimeoutMs)
        val results = runCatching { tester.doTest() }.getOrNull() ?: return null
        if (results.any { it <= 0 }) return null
        return HealthResult(results.maxOrNull() ?: 0)
    }

    private fun resolveServerHost(profile: ProxyEntity): String? {
        val bean = profile.requireBean()
        val direct = bean.serverAddress?.takeIf { it.isNotBlank() && it != "127.0.0.1" }
        if (direct != null) return direct

        val configBean = profile.configBean ?: return null
        val raw = configBean.config.takeIf { it.isNotBlank() } ?: return null
        return runCatching {
            val json = JSONObject(raw)
            when {
                json.has("server") -> json.optString("server")
                json.has("address") -> json.optString("address")
                json.has("server_address") -> json.optString("server_address")
                else -> ""
            }.takeIf { it.isNotBlank() }
        }.getOrNull()
    }

    private fun flagFromCountryCode(code: String): String {
        val c = code.uppercase(Locale.US)
        if (c.length != 2) return "??"
        val first = Character.codePointAt(c, 0) - 0x41 + 0x1F1E6
        val second = Character.codePointAt(c, 1) - 0x41 + 0x1F1E6
        return String(Character.toChars(first)) + String(Character.toChars(second))
    }

    private data class HealthResult(val latencyMs: Int)

    private class MultiUrlTest(
        profile: ProxyEntity,
        private val links: List<String>,
        private val timeout: Int
    ) : BoxInstance(profile) {

        suspend fun doTest(): List<Int> {
            return suspendCoroutine { c ->
                processes = GuardedProcessPool {
                    Logs.w(it)
                    c.tryResumeWithException(it)
                }
                runOnDefaultDispatcher {
                    use {
                        try {
                            init()
                            launch()
                            if (processes.processCount > 0) {
                                delay(500)
                            }
                            val results = links.map { link ->
                                Libcore.urlTest(box, link, timeout)
                            }
                            c.tryResume(results)
                        } catch (e: Exception) {
                            c.tryResumeWithException(e)
                        }
                    }
                }
            }
        }

        override fun buildConfig() {
            config = buildConfig(profile, true)
        }
    }

    private data class GeoInfo(
        val country: String,
        val countryCode: String,
        val city: String
    )

    private object GeoResolver {
        suspend fun resolve(host: String): GeoInfo? {
            val ip = resolveIp(host) ?: return null
            return queryIpApi(ip)
                ?: queryIpApiCo(ip)
                ?: queryIpInfo(ip)
        }

        private fun resolveIp(host: String): String? {
            return runCatching { InetAddress.getByName(host).hostAddress }.getOrNull()
        }

        private fun queryIpApi(ip: String): GeoInfo? {
            val url = "http://ip-api.com/json/${URLEncoder.encode(ip, "UTF-8")}" +
                "?fields=status,country,countryCode,city,regionName"
            val json = httpGetJson(url) ?: return null
            if (json.optString("status") != "success") return null
            val city = json.optString("city").ifBlank { json.optString("regionName") }
            return GeoInfo(
                country = json.optString("country"),
                countryCode = json.optString("countryCode"),
                city = city
            )
        }

        private fun queryIpApiCo(ip: String): GeoInfo? {
            val url = "https://ipapi.co/${URLEncoder.encode(ip, "UTF-8")}/json/"
            val json = httpGetJson(url) ?: return null
            val country = json.optString("country_name")
            val code = json.optString("country_code")
            if (country.isBlank() || code.isBlank()) return null
            return GeoInfo(country, code, json.optString("city"))
        }

        private fun queryIpInfo(ip: String): GeoInfo? {
            val url = "https://ipinfo.io/${URLEncoder.encode(ip, "UTF-8")}/json"
            val json = httpGetJson(url) ?: return null
            val code = json.optString("country")
            if (code.isBlank()) return null
            val countryName = Locale("", code).displayCountry.ifBlank { code }
            return GeoInfo(countryName, code, json.optString("city"))
        }

        private fun httpGetJson(url: String): JSONObject? {
            return runCatching {
                val response = Libcore.newHttpClient().newRequest().apply {
                    setURL(url)
                }.execute()
                val body = Util.getStringBox(response.contentString)
                JSONObject(body)
            }.getOrNull()
        }
    }
}
