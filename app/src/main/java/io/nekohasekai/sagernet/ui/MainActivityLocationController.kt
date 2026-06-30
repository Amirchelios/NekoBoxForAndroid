package io.nekohasekai.sagernet.ui

import android.view.View
import androidx.core.view.isVisible
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.bg.BaseService
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.databinding.LayoutMainBinding
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import io.nekohasekai.sagernet.ktx.readableMessage
import io.nekohasekai.sagernet.utils.ClashApiClient
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
    private var pickerJob: Job? = null
    private var reconnectSyncJob: Job? = null

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
                    val savedFlag = DataStore.yacdSelectedFlag.takeIf { it.isNotBlank() }
                    if (savedFlag != null) {
                        lastLocationFlag = savedFlag
                    } else if (!locationFetchInFlight && now - lastLocationFetchAt >= 5000L) {
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
        pickerJob?.cancel()
        pickerJob = null
        reconnectSyncJob?.cancel()
        reconnectSyncJob = null
        locationFetchInFlight = false
        lastLocationFlag = null
        lastLocationFetchAt = 0L
        updateLocationCard(forceHide = true)
    }

    fun syncSavedLocationAfterReconnect() {
        val savedProxy = DataStore.yacdSelectedProxy
        if (savedProxy.isBlank()) return
        if (reconnectSyncJob?.isActive == true) return
        reconnectSyncJob = activity.lifecycleScope.launch {
            val flag = DataStore.yacdSelectedFlag.takeIf { it.isNotBlank() }
            if (flag != null) {
                binding.locationFlag.text = flag
                lastLocationFlag = flag
            }
            val ok = syncSavedLocation()
            if (!ok) {
                Logs.w("Saved dashboard location could not be restored: $savedProxy")
            }
        }
    }

    fun showLocationPicker() {
        if (DataStore.serviceState != BaseService.State.Connected) {
            activity.snackbar(R.string.dashboard_api_unavailable).show()
            return
        }
        if (pickerJob?.isActive == true) return
        pickerJob = activity.lifecycleScope.launch {
            binding.locationSwitch.animate().rotationBy(180f).setDuration(240L).start()
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val client = ClashApiClient()
                    val snapshot = client.fetchProxies()
                    val choices = buildLocationChoices(snapshot)
                    PickerData(client, snapshot, choices)
                }
            }
            result.onSuccess { pickerData ->
                showPickerDialog(pickerData)
            }.onFailure {
                Logs.w(it)
                activity.snackbar(activity.getString(R.string.location_picker_failed, it.readableMessage)).show()
            }
        }
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

    private fun buildLocationChoices(
        snapshot: ClashApiClient.ProxySnapshot,
    ): List<LocationChoice> {
        val byFlag = linkedMapOf<String, MutableList<ClashApiClient.ProxyItem>>()
        for (proxy in snapshot.proxies.values) {
            if (!proxy.isSelectableProxy) continue
            val flag = extractFlag(proxy.name) ?: continue
            if (proxy.historyDelay != null && proxy.historyDelay <= 0) continue
            byFlag.getOrPut(flag) { mutableListOf() }.add(proxy)
        }
        return byFlag.entries
            .sortedBy { it.key }
            .map { (flag, proxies) ->
                val sorted = proxies.sortedWith(
                    compareBy<ClashApiClient.ProxyItem> { it.historyDelay ?: Int.MAX_VALUE }
                        .thenBy { it.name.lowercase(Locale.US) }
                )
                LocationChoice(flag, sorted)
            }
    }

    private fun showPickerDialog(data: PickerData) {
        val autoGroup = data.snapshot.preferredFallbackGroupName()
        val autoName = autoGroup?.let { group ->
            data.snapshot.proxies[group]?.all?.firstOrNull { it.equals("auto", ignoreCase = true) }
        }
        val entries = arrayListOf<String>()
        val displayFlags = arrayListOf<String?>()
        val actions = arrayListOf<suspend () -> AppliedLocation?>()
        if (autoGroup != null && autoName != null) {
            entries.add(activity.getString(R.string.location_picker_auto))
            displayFlags.add("🌍")
            actions.add {
                if (data.client.switchProxy(autoGroup, autoName)) {
                    AppliedLocation(autoGroup, autoName, "🌍")
                } else {
                    null
                }
            }
        }
        for (choice in data.choices) {
            val best = choice.proxies.first()
            val delay = best.historyDelay?.let { " · ${it}ms" }.orEmpty()
            entries.add("${choice.flag}  ${choice.proxies.size}$delay")
            displayFlags.add(choice.flag)
            actions.add {
                val group = data.snapshot.preferredGroupNameFor(best.name)
                if (group != null && data.client.switchProxy(group, best.name)) {
                    AppliedLocation(group, best.name, choice.flag)
                } else {
                    null
                }
            }
        }
        if (entries.isEmpty()) {
            activity.snackbar(R.string.location_picker_empty).show()
            return
        }

        MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.location_picker_title)
            .setItems(entries.toTypedArray()) { _, which ->
                pickerJob?.cancel()
                pickerJob = activity.lifecycleScope.launch {
                    val applied = withContext(Dispatchers.IO) {
                        runCatching { actions[which].invoke() }.getOrNull()
                    }
                    if (applied != null) {
                        DataStore.yacdSelectedGroup = applied.group
                        DataStore.yacdSelectedProxy = applied.proxy
                        DataStore.yacdSelectedFlag = applied.flag
                        val flag = displayFlags[which] ?: applied.flag
                        if (!flag.isNullOrBlank()) {
                            binding.locationFlag.text = flag
                            lastLocationFlag = flag
                        }
                        activity.snackbar(R.string.location_picker_applied).show()
                    } else {
                        activity.snackbar(R.string.location_picker_apply_failed).show()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun extractFlag(name: String): String? {
        val match = FLAG_REGEX.find(name) ?: return null
        return match.value
    }

    private suspend fun syncSavedLocation(): Boolean {
        val savedProxy = DataStore.yacdSelectedProxy.takeIf { it.isNotBlank() } ?: return false
        val savedGroup = DataStore.yacdSelectedGroup.takeIf { it.isNotBlank() }
        val savedFlag = DataStore.yacdSelectedFlag.takeIf { it.isNotBlank() }
        val client = ClashApiClient()
        repeat(RECONNECT_SYNC_ATTEMPTS) {
            val ready = withContext(Dispatchers.IO) { client.isReady() }
            if (ready) {
                val snapshot = withContext(Dispatchers.IO) { client.fetchProxies() }
                val target = when {
                    snapshot.proxies.containsKey(savedProxy) -> savedProxy
                    savedFlag != null -> findBestProxyForFlag(snapshot, savedFlag)
                    else -> null
                } ?: return false
                val group = savedGroup
                    ?.takeIf { snapshot.proxies[it]?.all?.contains(target) == true }
                    ?: snapshot.preferredGroupNameFor(target)
                    ?: return false
                val ok = withContext(Dispatchers.IO) { client.switchProxy(group, target) }
                if (ok && target != savedProxy) {
                    DataStore.yacdSelectedGroup = group
                    DataStore.yacdSelectedProxy = target
                }
                return ok
            }
            delay(RECONNECT_SYNC_DELAY_MS)
        }
        return false
    }

    private fun findBestProxyForFlag(
        snapshot: ClashApiClient.ProxySnapshot,
        flag: String,
    ): String? {
        return snapshot.proxies.values
            .asSequence()
            .filter { it.isSelectableProxy }
            .filter { extractFlag(it.name) == flag }
            .sortedWith(
                compareBy<ClashApiClient.ProxyItem> { it.historyDelay ?: Int.MAX_VALUE }
                    .thenBy { it.name.lowercase(Locale.US) }
            )
            .firstOrNull()
            ?.name
    }

    private data class PickerData(
        val client: ClashApiClient,
        val snapshot: ClashApiClient.ProxySnapshot,
        val choices: List<LocationChoice>,
    )

    private data class AppliedLocation(
        val group: String,
        val proxy: String,
        val flag: String,
    )

    private data class LocationChoice(
        val flag: String,
        val proxies: List<ClashApiClient.ProxyItem>,
    )

    private companion object {
        val FLAG_REGEX = Regex("[\\x{1F1E6}-\\x{1F1FF}]{2}")
        const val RECONNECT_SYNC_ATTEMPTS = 12
        const val RECONNECT_SYNC_DELAY_MS = 350L
    }
}
