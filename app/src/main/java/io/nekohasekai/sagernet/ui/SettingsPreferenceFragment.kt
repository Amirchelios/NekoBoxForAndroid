package io.nekohasekai.sagernet.ui

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import androidx.core.app.ActivityCompat
import androidx.preference.*
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.preference.EditTextPreferenceModifiers
import io.nekohasekai.sagernet.ktx.*
import io.nekohasekai.sagernet.utils.Theme
import moe.matsuri.nb4a.ui.*

class SettingsPreferenceFragment : PreferenceFragmentCompat() {

    private lateinit var isProxyApps: SwitchPreference

    private lateinit var globalCustomConfig: EditConfigPreference
    private lateinit var smartProfilePreset: SimpleMenuPreference
    private lateinit var smartEnableNetworkLearning: SwitchPreference
    private lateinit var smartDebugPanel: Preference


    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        listView.layoutManager = FixedLinearLayoutManager(listView)
    }

    private val reloadListener = Preference.OnPreferenceChangeListener { _, _ ->
        needReload()
        true
    }

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        preferenceManager.preferenceDataStore = DataStore.configurationStore
        DataStore.initGlobal()
        addPreferencesFromResource(R.xml.global_preferences)

        val appTheme = findPreference<ColorPickerPreference>(Key.APP_THEME)!!
        appTheme.setOnPreferenceChangeListener { _, newTheme ->
            if (DataStore.serviceState.started) {
                SagerNet.reloadService()
            }
            val theme = Theme.getTheme(newTheme as Int)
            app.setTheme(theme)
            requireActivity().apply {
                setTheme(theme)
                ActivityCompat.recreate(this)
            }
            true
        }

        val nightTheme = findPreference<SimpleMenuPreference>(Key.NIGHT_THEME)!!
        nightTheme.setOnPreferenceChangeListener { _, newTheme ->
            Theme.currentNightMode = (newTheme as String).toInt()
            Theme.applyNightTheme()
            true
        }
        val mixedPort = findPreference<EditTextPreference>(Key.MIXED_PORT)!!
        val serviceMode = findPreference<Preference>(Key.SERVICE_MODE)!!
        val allowAccess = findPreference<Preference>(Key.ALLOW_ACCESS)!!
        val appendHttpProxy = findPreference<SwitchPreference>(Key.APPEND_HTTP_PROXY)!!

        val showDirectSpeed = findPreference<SwitchPreference>(Key.SHOW_DIRECT_SPEED)!!
        val ipv6Mode = findPreference<Preference>(Key.IPV6_MODE)!!
        val trafficSniffing = findPreference<Preference>(Key.TRAFFIC_SNIFFING)!!

        val bypassLan = findPreference<SwitchPreference>(Key.BYPASS_LAN)!!
        val bypassLanInCore = findPreference<SwitchPreference>(Key.BYPASS_LAN_IN_CORE)!!

        val remoteDns = findPreference<EditTextPreference>(Key.REMOTE_DNS)!!
        val directDns = findPreference<EditTextPreference>(Key.DIRECT_DNS)!!
        val enableDnsRouting = findPreference<SwitchPreference>(Key.ENABLE_DNS_ROUTING)!!
        val enableFakeDns = findPreference<SwitchPreference>(Key.ENABLE_FAKEDNS)!!

        val logLevel = findPreference<LongClickListPreference>(Key.LOG_LEVEL)!!
        val mtu = findPreference<MTUPreference>(Key.MTU)!!
        globalCustomConfig = findPreference(Key.GLOBAL_CUSTOM_CONFIG)!!
        globalCustomConfig.useConfigStore(Key.GLOBAL_CUSTOM_CONFIG)
        smartProfilePreset = findPreference("smartProfilePreset")!!
        smartEnableNetworkLearning = findPreference("smartEnableNetworkLearning")!!
        smartDebugPanel = findPreference("smartDebugPanel")!!

        logLevel.dialogLayoutResource = R.layout.layout_loglevel_help
        logLevel.setOnPreferenceChangeListener { _, _ ->
            needRestart()
            true
        }
        logLevel.setOnLongClickListener {
            if (context == null) return@setOnLongClickListener true

            val view = EditText(context).apply {
                inputType = EditorInfo.TYPE_CLASS_NUMBER
                var size = DataStore.logBufSize
                if (size == 0) size = 50
                setText(size.toString())
            }

            MaterialAlertDialogBuilder(requireContext()).setTitle("Log buffer size (kb)")
                .setView(view)
                .setPositiveButton(android.R.string.ok) { _, _ ->
                    DataStore.logBufSize = view.text.toString().toInt()
                    if (DataStore.logBufSize <= 0) DataStore.logBufSize = 50
                    needRestart()
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
            true
        }

        mixedPort.setOnBindEditTextListener(EditTextPreferenceModifiers.Port)

        val metedNetwork = findPreference<Preference>(Key.METERED_NETWORK)!!
        if (Build.VERSION.SDK_INT < 28) {
            metedNetwork.remove()
        }
        isProxyApps = findPreference(Key.PROXY_APPS)!!
        isProxyApps.setOnPreferenceChangeListener { _, newValue ->
            startActivity(Intent(activity, AppManagerActivity::class.java))
            if (newValue as Boolean) DataStore.dirty = true
            newValue
        }

        val profileTrafficStatistics =
            findPreference<SwitchPreference>(Key.PROFILE_TRAFFIC_STATISTICS)!!
        val speedInterval = findPreference<SimpleMenuPreference>(Key.SPEED_INTERVAL)!!
        profileTrafficStatistics.isEnabled = speedInterval.value.toString() != "0"
        speedInterval.setOnPreferenceChangeListener { _, newValue ->
            profileTrafficStatistics.isEnabled = newValue.toString() != "0"
            needReload()
            true
        }

        serviceMode.setOnPreferenceChangeListener { _, _ ->
            if (DataStore.serviceState.started) SagerNet.stopService()
            true
        }

        val tunImplementation = findPreference<SimpleMenuPreference>(Key.TUN_IMPLEMENTATION)!!
        val resolveDestination = findPreference<SwitchPreference>(Key.RESOLVE_DESTINATION)!!
        val acquireWakeLock = findPreference<SwitchPreference>(Key.ACQUIRE_WAKE_LOCK)!!
        val enableClashAPI = findPreference<SwitchPreference>(Key.ENABLE_CLASH_API)!!
        enableClashAPI.setOnPreferenceChangeListener { _, newValue ->
            (activity as MainActivity?)?.refreshNavMenu(newValue as Boolean)
            needReload()
            true
        }

        mixedPort.onPreferenceChangeListener = reloadListener
        appendHttpProxy.onPreferenceChangeListener = reloadListener
        showDirectSpeed.onPreferenceChangeListener = reloadListener
        trafficSniffing.onPreferenceChangeListener = reloadListener
        bypassLan.onPreferenceChangeListener = reloadListener
        bypassLanInCore.onPreferenceChangeListener = reloadListener
        mtu.onPreferenceChangeListener = reloadListener

        enableFakeDns.onPreferenceChangeListener = reloadListener
        remoteDns.onPreferenceChangeListener = reloadListener
        directDns.onPreferenceChangeListener = reloadListener
        enableDnsRouting.onPreferenceChangeListener = reloadListener

        ipv6Mode.onPreferenceChangeListener = reloadListener
        allowAccess.onPreferenceChangeListener = reloadListener

        resolveDestination.onPreferenceChangeListener = reloadListener
        tunImplementation.onPreferenceChangeListener = reloadListener
        acquireWakeLock.onPreferenceChangeListener = reloadListener
        globalCustomConfig.onPreferenceChangeListener = reloadListener
        smartEnableNetworkLearning.onPreferenceChangeListener = reloadListener

        smartProfilePreset.setOnPreferenceChangeListener { _, newValue ->
            applySmartProfilePreset(newValue?.toString().orEmpty())
            needReload()
            true
        }
        smartDebugPanel.setOnPreferenceClickListener {
            smartDebugPanel.summary = buildSmartDebugSummary()
            true
        }
    }

    override fun onResume() {
        super.onResume()

        if (::isProxyApps.isInitialized) {
            isProxyApps.isChecked = DataStore.proxyApps
        }
        if (::globalCustomConfig.isInitialized) {
            globalCustomConfig.notifyChanged()
        }
        if (::smartDebugPanel.isInitialized) {
            smartDebugPanel.summary = buildSmartDebugSummary()
        }
    }

    private fun applySmartProfilePreset(preset: String) {
        when (preset) {
            "gaming" -> {
                DataStore.parallelConcurrency = 24
                DataStore.connectionTestConcurrent = 24
                DataStore.smartSwitchCooldownSec = 45
                DataStore.smartSwitchMinDwellSec = 45
                DataStore.smartSwitchProbeIntervalSec = 16
                DataStore.smartSwitchBadProbeIntervalSec = 5
                DataStore.smartSwitchCandidateWins = 2
                DataStore.smartSwitchCandidateWinsWarmup = 1
                DataStore.smartSwitchMinImproveAbs = 140
                DataStore.smartSwitchMinImprovePct = 12
                DataStore.smartSwitchStableLockSec = 300
                DataStore.smartSwitchExcellentScore = 620
                DataStore.smartSwitchMinThroughputGainPct = 28
            }

            "streaming", "stable" -> {
                DataStore.smartSwitchCooldownSec = 180
                DataStore.smartSwitchMinDwellSec = 240
                DataStore.smartSwitchProbeIntervalSec = 45
                DataStore.smartSwitchBadProbeIntervalSec = 12
                DataStore.smartSwitchCandidateWins = 5
                DataStore.smartSwitchCandidateWinsWarmup = 3
                DataStore.smartSwitchMinImproveAbs = 320
                DataStore.smartSwitchMinImprovePct = 24
                DataStore.smartSwitchStableLockSec = 1200
                DataStore.smartSwitchExcellentScore = 820
                DataStore.smartSwitchMinThroughputGainPct = 24
            }

            "download", "max_download" -> {
                DataStore.parallelConcurrency = 28
                DataStore.connectionTestConcurrent = 24
                DataStore.smartSwitchCooldownSec = 90
                DataStore.smartSwitchMinDwellSec = 90
                DataStore.smartSwitchProbeIntervalSec = 22
                DataStore.smartSwitchBadProbeIntervalSec = 8
                DataStore.smartSwitchCandidateWins = 3
                DataStore.smartSwitchCandidateWinsWarmup = 2
                DataStore.smartSwitchMinImproveAbs = 180
                DataStore.smartSwitchMinImprovePct = 14
                DataStore.smartSwitchStableLockSec = 600
                DataStore.smartSwitchExcellentScore = 680
                DataStore.smartSwitchMinThroughputGainPct = 10
            }

            "manual" -> {
                DataStore.smartSwitchCooldownSec = 300
                DataStore.smartSwitchMinDwellSec = 600
                DataStore.smartSwitchProbeIntervalSec = 60
                DataStore.smartSwitchBadProbeIntervalSec = 20
                DataStore.smartSwitchCandidateWins = 5
                DataStore.smartSwitchCandidateWinsWarmup = 3
                DataStore.smartSwitchMinImproveAbs = 400
                DataStore.smartSwitchMinImprovePct = 30
                DataStore.smartSwitchStableLockSec = 1800
                DataStore.smartSwitchExcellentScore = 900
                DataStore.smartSwitchMinThroughputGainPct = 30
            }

            else -> {
                DataStore.smartSwitchCooldownSec = 120
                DataStore.smartSwitchMinDwellSec = 150
                DataStore.smartSwitchProbeIntervalSec = 30
                DataStore.smartSwitchBadProbeIntervalSec = 10
                DataStore.smartSwitchCandidateWins = 4
                DataStore.smartSwitchCandidateWinsWarmup = 2
                DataStore.smartSwitchMinImproveAbs = 260
                DataStore.smartSwitchMinImprovePct = 20
                DataStore.smartSwitchStableLockSec = 900
                DataStore.smartSwitchExcellentScore = 760
                DataStore.smartSwitchMinThroughputGainPct = 18
            }
        }
    }

    private fun buildSmartDebugSummary(): String {
        val health = DataStore.smartSessionHealth
        val decision = DataStore.smartLastDecision.ifBlank { "idle" }
        return getString(R.string.smart_debug_health) + ": " + health + "/100\n" +
            getString(R.string.smart_debug_last_decision) + ": " + decision
    }

}
