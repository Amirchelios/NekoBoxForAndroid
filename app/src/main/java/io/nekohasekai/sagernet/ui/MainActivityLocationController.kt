package io.nekohasekai.sagernet.ui

import android.view.View
import androidx.core.view.isVisible
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.bg.BaseService
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.databinding.LayoutMainBinding
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import libcore.Libcore
import moe.matsuri.nb4a.utils.Util
import org.json.JSONObject
import java.util.Locale

class MainActivityLocationController(
    private val activity: MainActivity,
    private val binding: LayoutMainBinding,
) {
    private var locationPollJob: Job? = null
    private var locationFetchInFlight = false
    private var lastLocationFlag: String? = null
    private var lastLocationFetchAt: Long = 0L

    fun start() {
        locationPollJob?.cancel()
        locationPollJob = activity.lifecycleScope.launch {
            while (isActive) {
                if (DataStore.serviceState == BaseService.State.Connected) {
                    if (!isOnMainScreen()) {
                        onMainDispatcher { updateLocationCard(forceHide = true) }
                        delay(1000L)
                        continue
                    }
                    val now = System.currentTimeMillis()
                    if (!locationFetchInFlight && now - lastLocationFetchAt >= 5000L) {
                        locationFetchInFlight = true
                        val flag = withContext(Dispatchers.IO) {
                            fetchIpLocationFlag()
                        } ?: "🌍"
                        lastLocationFetchAt = now
                        lastLocationFlag = flag
                        locationFetchInFlight = false
                    }
                    val flagToShow = lastLocationFlag ?: "🌍"
                    onMainDispatcher {
                        binding.locationFlag.text = flagToShow
                        updateLocationCard()
                    }
                } else {
                    onMainDispatcher { updateLocationCard(forceHide = true) }
                }
                delay(5000L)
            }
        }
    }

    fun stop() {
        locationPollJob?.cancel()
        locationPollJob = null
        locationFetchInFlight = false
        lastLocationFlag = null
        lastLocationFetchAt = 0L
        updateLocationCard(forceHide = true)
    }

    private fun updateLocationCard(forceHide: Boolean = false) {
        val card = binding.locationCard
        if (forceHide || !isOnMainScreen()) {
            card.animate().cancel()
            card.alpha = 0f
            card.visibility = View.GONE
            return
        }
        if (card.visibility != View.VISIBLE) {
            card.visibility = View.VISIBLE
            card.alpha = 0f
            card.scaleX = 0.96f
            card.scaleY = 0.96f
            card.animate()
                .alpha(1f)
                .scaleX(1f)
                .scaleY(1f)
                .setDuration(360L)
                .start()
        }
    }

    private fun isOnMainScreen(): Boolean {
        return activity.supportFragmentManager.findFragmentById(R.id.fragment_holder) is ConfigurationFragment
    }

    private fun fetchIpLocationFlag(): String? {
        val urls = listOf(
            "http://ip-api.com/json/?fields=status,countryCode",
            "https://ipapi.co/json/",
            "https://ipinfo.io/json"
        )
        for (url in urls) {
            val json = httpGetJson(url) ?: continue
            val code = when {
                json.has("countryCode") -> json.optString("countryCode")
                json.has("country_code") -> json.optString("country_code")
                json.has("country") -> json.optString("country")
                else -> ""
            }.uppercase(Locale.US)
            if (code.length == 2) {
                return countryCodeToFlag(code)
            }
        }
        return null
    }

    private fun httpGetJson(url: String): JSONObject? {
        return runCatching {
            val response = Libcore.newHttpClient().newRequest().apply { setURL(url) }.execute()
            val body = Util.getStringBox(response.contentString)
            JSONObject(body)
        }.onFailure {
            Logs.w(it)
        }.getOrNull()
    }

    private fun countryCodeToFlag(code: String): String {
        val upper = code.uppercase(Locale.US)
        val first = 0x1F1E6 + (upper[0] - 'A')
        val second = 0x1F1E6 + (upper[1] - 'A')
        return String(Character.toChars(first)) + String(Character.toChars(second))
    }
}
