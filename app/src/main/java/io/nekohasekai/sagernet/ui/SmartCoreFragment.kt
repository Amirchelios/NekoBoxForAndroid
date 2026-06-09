package io.nekohasekai.sagernet.ui

import android.os.Bundle
import android.text.format.Formatter
import android.view.View
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.preference.ListPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.bg.proto.SmartLearningEngine
import io.nekohasekai.sagernet.bg.BaseService
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.ktx.app
import io.nekohasekai.sagernet.ktx.needReload
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class SmartCoreFragment : NamedFragment(R.layout.layout_smart_core) {

    override fun name0() = app.getString(R.string.smart_core)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        if (savedInstanceState == null) {
            childFragmentManager.beginTransaction()
                .replace(R.id.smart_core_settings, SmartCorePreferenceFragment())
                .commitAllowingStateLoss()
        }
    }
}

class SmartCorePreferenceFragment : PreferenceFragmentCompat() {

    private lateinit var activeServer: Preference
    private lateinit var standbyServer: Preference
    private lateinit var health: Preference
    private lateinit var decision: Preference
    private lateinit var quarantine: Preference

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        preferenceManager.preferenceDataStore = DataStore.configurationStore
        addPreferencesFromResource(R.xml.smart_core_preferences)

        activeServer = findPreference("smartStatusActive")!!
        standbyServer = findPreference("smartStatusStandby")!!
        health = findPreference("smartStatusHealth")!!
        decision = findPreference("smartStatusDecision")!!
        quarantine = findPreference("smartStatusQuarantine")!!

        findPreference<Preference>("smartStatusRefresh")!!.setOnPreferenceClickListener {
            refreshStatus()
            true
        }
        findPreference<ListPreference>("smartProfilePreset")!!.setOnPreferenceChangeListener { _, newValue ->
            DataStore.applySmartProfilePreset(newValue.toString())
            needReload()
            true
        }
        findPreference<ListPreference>("smartSwitchSensitivity")!!.setOnPreferenceChangeListener { _, _ ->
            needReload()
            true
        }
        findPreference<Preference>("smartInterruptExistingConnections")!!.setOnPreferenceChangeListener { _, _ ->
            needReload()
            true
        }
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                while (true) {
                    refreshStatus()
                    delay(2_000L)
                }
            }
        }
    }

    private fun refreshStatus() {
        val service = (activity as? MainActivity)?.connection?.service
        val serviceState = service?.let {
            runCatching { BaseService.State.values()[it.state] }.getOrNull()
        } ?: DataStore.serviceState
        val runtimeActiveId = service?.let { runCatching { it.smartActiveProxyId }.getOrDefault(0L) } ?: 0L
        val runtimeGroupId = service?.let { runCatching { it.smartRuntimeGroupId }.getOrDefault(0L) } ?: 0L
        val runtimeStandbyId = service?.let { runCatching { it.smartStandbyProxyId }.getOrDefault(0L) } ?: 0L
        val runtimeHealth = service?.let { runCatching { it.smartSessionHealth }.getOrDefault(0) }
            ?: DataStore.smartSessionHealth
        val runtimeTxRate = service?.let { runCatching { it.smartTxRate }.getOrDefault(0L) }
            ?: DataStore.smartMainTxRate
        val runtimeRxRate = service?.let { runCatching { it.smartRxRate }.getOrDefault(0L) }
            ?: DataStore.smartMainRxRate
        val runtimeDecision = service?.let { runCatching { it.smartLastDecision }.getOrNull() }
            ?: DataStore.smartLastDecision
        val groupId = runtimeGroupId.takeIf { it > 0L } ?: DataStore.selectedGroup
        val ambientHealthy = SmartLearningEngine.probeAmbientNetwork()

        val activeId = if (serviceState == BaseService.State.Connected) {
            runtimeActiveId.takeIf { it > 0L }
                ?: SmartLearningEngine.preferredProxy(groupId)
        } else {
            0L
        }
        val order = SmartLearningEngine.preferredOrder(groupId)
        val standbyId = runtimeStandbyId.takeIf { it > 0L }
            ?: order.firstOrNull { it != activeId }
            ?: 0L
        val profiles = SagerDatabase.proxyDao.getByGroup(groupId)
        val profileMap = profiles.associateBy { it.id }

        activeServer.summary = describeProfile(SagerDatabase.proxyDao.getById(activeId))
        standbyServer.summary = describeProfile(profileMap[standbyId])
        health.summary = getString(
            R.string.smart_status_health_detail,
            runtimeHealth.coerceIn(0, 100),
            runtimeTxRate,
            runtimeRxRate,
        ) + "\n" + if (ambientHealthy) {
            "network=ok"
        } else {
            "network=degraded"
        }
        decision.summary = runtimeDecision.ifBlank { getString(R.string.smart_status_no_decision) }

        val now = System.currentTimeMillis()
        val quarantined = profiles.filter { SmartLearningEngine.isQuarantined(it.id, now) }
        quarantine.summary = if (quarantined.isEmpty()) {
            getString(R.string.smart_status_none)
        } else {
            quarantined.joinToString("\n") {
                val remaining = TimeUnit.MILLISECONDS.toMinutes(
                    (SmartLearningEngine.getSummary(it.id).quarantineUntil - now).coerceAtLeast(0L)
                ).coerceAtLeast(1L)
                getString(R.string.smart_status_quarantine_item, it.displayName(), remaining)
            }
        }
    }

    private fun describeProfile(profile: ProxyEntity?): String {
        if (profile == null) return getString(R.string.smart_status_none)
        val summary = SmartLearningEngine.getSummary(profile.id)
        val score = summary.lastScore
        val bandwidth = summary.lastBandwidthKbps
        val streak = summary.failureStreak
        val emaScore = SmartLearningEngine.getEma(profile.id, "score")
        val emaBandwidth = SmartLearningEngine.getEma(profile.id, "bandwidth")
        val latency = if (score > 0) getString(R.string.smart_status_latency, score) else "-"
        val speed = if (bandwidth > 0) {
            Formatter.formatFileSize(requireContext(), bandwidth.toLong() * 1000L / 8L) + "/s"
        } else {
            "-"
        }
        return getString(
            R.string.smart_status_profile_detail,
            profile.displayName(),
            latency,
            speed,
            streak
        ) + "\n" +
            "ema_score=" + if (emaScore >= 0) emaScore else "-" +
            " ema_bw=" + if (emaBandwidth >= 0) emaBandwidth else "-" +
            "\n" + SmartLearningEngine.formatSummary(profile.id)
    }
}
