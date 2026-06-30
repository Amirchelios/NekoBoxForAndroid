package io.nekohasekai.sagernet.ui

import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.core.content.ContextCompat
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
            val delay = proxy.historyDelay ?: continue
            if (delay <= 0) continue
            if (snapshot.preferredGroupNameFor(proxy.name) == null) continue
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
        val rows = arrayListOf<PickerRow>()
        if (autoGroup != null && autoName != null) {
            rows.add(PickerRow(
                title = activity.getString(R.string.location_picker_auto),
                subtitle = autoGroup,
                flag = "🌍",
            ) {
                if (data.client.switchProxy(autoGroup, autoName)) {
                    data.client.closeStaleConnections(autoGroup, autoName)
                    AppliedLocation(autoGroup, autoName, "🌍")
                } else {
                    null
                }
            })
        }
        val verifiedRows = data.choices.map { choice ->
            val best = choice.proxies.first()
            PickerRow(
                title = shortProxyTitle(best.name, choice.flag),
                subtitle = activity.resources.getQuantityString(
                    R.plurals.location_picker_server_count,
                    choice.proxies.size,
                    choice.proxies.size
                ),
                flag = choice.flag,
                delayMs = best.historyDelay,
            ) {
                val group = data.snapshot.preferredGroupNameFor(best.name)
                if (group != null && data.client.switchProxy(group, best.name)) {
                    data.client.closeStaleConnections(group, best.name)
                    AppliedLocation(group, best.name, choice.flag)
                } else {
                    null
                }
            }
        }
        rows.addAll(verifiedRows)
        if (rows.isEmpty()) {
            activity.snackbar(R.string.location_picker_empty).show()
            return
        }

        lateinit var dialog: androidx.appcompat.app.AlertDialog
        val content = buildPickerView(
            rows = rows,
            onPick = { row ->
                dialog.dismiss()
                applyPickerRow(row)
            }
        )
        dialog = MaterialAlertDialogBuilder(activity)
            .setView(content)
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        dialog.show()
    }

    private fun buildPickerView(
        rows: List<PickerRow>,
        onPick: (PickerRow) -> Unit,
    ): View {
        val density = activity.resources.displayMetrics.density
        fun dp(value: Int) = (value * density).toInt()
        val root = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(8))
        }
        root.addView(TextView(activity).apply {
            text = activity.getString(R.string.location_picker_title)
            textSize = 20f
            setTextColor(ContextCompat.getColor(activity, R.color.app_on_surface))
            typeface = android.graphics.Typeface.DEFAULT_BOLD
        })
        root.addView(TextView(activity).apply {
            text = activity.getString(R.string.location_picker_verified_summary)
            textSize = 13f
            setTextColor(ContextCompat.getColor(activity, R.color.app_on_surface_muted))
            setPadding(0, dp(6), 0, dp(14))
        })

        val list = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        addRows(list, rows.filter { it.title == activity.getString(R.string.location_picker_auto) }, onPick)
        addRows(list, rows.filter { it.title != activity.getString(R.string.location_picker_auto) }, onPick, R.string.location_picker_verified)

        root.addView(ScrollView(activity).apply {
            addView(list)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(390)
            )
        })
        return root
    }

    private fun addRows(
        parent: LinearLayout,
        rows: List<PickerRow>,
        onPick: (PickerRow) -> Unit,
        titleRes: Int? = null,
    ) {
        if (rows.isEmpty()) return
        val density = activity.resources.displayMetrics.density
        fun dp(value: Int) = (value * density).toInt()
        if (titleRes != null) {
            parent.addView(TextView(activity).apply {
                text = activity.getString(titleRes)
                textSize = 12f
                setTextColor(ContextCompat.getColor(activity, R.color.app_on_surface_muted))
                typeface = android.graphics.Typeface.DEFAULT_BOLD
                setPadding(0, dp(10), 0, dp(6))
            })
        }
        for (row in rows) {
            parent.addView(LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = android.view.Gravity.CENTER_VERTICAL
                background = ContextCompat.getDrawable(activity, R.drawable.bg_location_picker_row)
                foreground = ContextCompat.getDrawable(activity, selectableItemBackground())
                isClickable = true
                isFocusable = true
                setPadding(dp(12), dp(10), dp(12), dp(10))
                setOnClickListener { onPick(row) }

                addView(TextView(activity).apply {
                    text = row.flag
                    textSize = 28f
                    gravity = android.view.Gravity.CENTER
                    layoutParams = LinearLayout.LayoutParams(dp(46), dp(46))
                })

                addView(LinearLayout(activity).apply {
                    orientation = LinearLayout.VERTICAL
                    layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                        .apply { marginStart = dp(10) }
                    addView(TextView(activity).apply {
                        text = row.title
                        textSize = 15f
                        maxLines = 1
                        ellipsize = android.text.TextUtils.TruncateAt.END
                        setTextColor(ContextCompat.getColor(activity, R.color.app_on_surface))
                        typeface = android.graphics.Typeface.DEFAULT_BOLD
                    })
                    addView(TextView(activity).apply {
                        text = row.subtitle
                        textSize = 12f
                        maxLines = 1
                        ellipsize = android.text.TextUtils.TruncateAt.END
                        setTextColor(ContextCompat.getColor(activity, R.color.app_on_surface_muted))
                    })
                })

                row.delayMs?.let { delay ->
                    addView(TextView(activity).apply {
                        text = "${delay}ms"
                        textSize = 12f
                        gravity = android.view.Gravity.CENTER
                        setTextColor(ContextCompat.getColor(activity, R.color.quick_update_text))
                        background = ContextCompat.getDrawable(activity, R.drawable.bg_location_picker_delay)
                        setPadding(dp(9), dp(5), dp(9), dp(5))
                        layoutParams = LinearLayout.LayoutParams(
                            ViewGroup.LayoutParams.WRAP_CONTENT,
                            ViewGroup.LayoutParams.WRAP_CONTENT
                        ).apply { marginStart = dp(10) }
                    })
                }
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    bottomMargin = dp(8)
                }
            })
        }
    }

    private fun selectableItemBackground(): Int {
        val outValue = android.util.TypedValue()
        activity.theme.resolveAttribute(android.R.attr.selectableItemBackground, outValue, true)
        return outValue.resourceId
    }

    private fun shortProxyTitle(raw: String, flag: String): String {
        return raw
            .replace(flag, "")
            .replace(Regex("\\s+"), " ")
            .trim()
            .ifBlank { activity.getString(R.string.location_picker_location) }
    }

    private fun applyPickerRow(row: PickerRow) {
        pickerJob?.cancel()
        pickerJob = activity.lifecycleScope.launch {
            val applied = withContext(Dispatchers.IO) {
                runCatching { row.action.invoke() }.getOrNull()
            }
            if (applied != null) {
                DataStore.yacdSelectedGroup = applied.group
                DataStore.yacdSelectedProxy = applied.proxy
                DataStore.yacdSelectedFlag = applied.flag
                binding.locationFlag.text = applied.flag
                lastLocationFlag = applied.flag
                activity.snackbar(R.string.location_picker_applied).show()
            } else {
                activity.snackbar(R.string.location_picker_apply_failed).show()
            }
        }
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
                val ok = withContext(Dispatchers.IO) {
                    val switched = client.switchProxy(group, target)
                    if (switched) client.closeStaleConnections(group, target)
                    switched
                }
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
            .filter { (it.historyDelay ?: 0) > 0 }
            .filter { snapshot.preferredGroupNameFor(it.name) != null }
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

    private data class PickerRow(
        val title: String,
        val subtitle: String,
        val flag: String,
        val delayMs: Int? = null,
        val action: suspend () -> AppliedLocation?,
    )

    private companion object {
        val FLAG_REGEX = Regex("[\\x{1F1E6}-\\x{1F1FF}]{2}")
        const val RECONNECT_SYNC_ATTEMPTS = 12
        const val RECONNECT_SYNC_DELAY_MS = 350L
    }
}
