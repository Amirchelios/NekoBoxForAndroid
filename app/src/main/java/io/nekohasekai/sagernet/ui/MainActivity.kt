package io.nekohasekai.sagernet.ui

import android.Manifest.permission.POST_NOTIFICATIONS
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.RemoteException
import android.view.Gravity
import android.view.KeyEvent
import android.view.MenuItem
import android.view.View
import android.view.animation.OvershootInterpolator
import androidx.activity.addCallback
import androidx.annotation.IdRes
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.isVisible
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.preference.PreferenceDataStore
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.navigation.NavigationView
import com.google.android.material.snackbar.Snackbar
import io.nekohasekai.sagernet.BuildConfig
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.aidl.ISagerNetService
import io.nekohasekai.sagernet.aidl.SpeedDisplayData
import io.nekohasekai.sagernet.aidl.TrafficData
import io.nekohasekai.sagernet.bg.BaseService
import io.nekohasekai.sagernet.bg.SagerConnection
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.GroupManager
import io.nekohasekai.sagernet.database.ProfileManager
import io.nekohasekai.sagernet.database.ProxyGroup
import io.nekohasekai.sagernet.database.SubscriptionBean
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.database.preference.OnPreferenceDataStoreChangeListener
import io.nekohasekai.sagernet.databinding.LayoutMainBinding
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.KryoConverters
import io.nekohasekai.sagernet.fmt.PluginEntry
import io.nekohasekai.sagernet.group.GroupInterfaceAdapter
import io.nekohasekai.sagernet.group.GroupUpdater
import io.nekohasekai.sagernet.ktx.alert
import io.nekohasekai.sagernet.ktx.isPlay
import io.nekohasekai.sagernet.ktx.isPreview
import io.nekohasekai.sagernet.ktx.launchCustomTab
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import io.nekohasekai.sagernet.ktx.parseProxies
import io.nekohasekai.sagernet.ktx.readableMessage
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import moe.matsuri.nb4a.utils.Util
import libcore.Libcore
import org.json.JSONObject
import java.util.Locale
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

class MainActivity : ThemedActivity(),
    SagerConnection.Callback,
    OnPreferenceDataStoreChangeListener,
    NavigationView.OnNavigationItemSelectedListener {

    lateinit var binding: LayoutMainBinding
    lateinit var navigation: NavigationView
    private val updateProgressListener = object : GroupUpdater.Listener {
        override fun onProgressChanged() {
            runOnUiThread { updateFabUpdateProgress() }
        }
    }
    private var internalProxyRestartJob: Job? = null
    private var pendingVpnStartJob: Job? = null
    private val importHandler by lazy { MainActivityImportHandler(this) }
    private val connectionAnimator by lazy { MainActivityConnectionAnimator(this, binding) }
    private val locationController by lazy { MainActivityLocationController(this, binding) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = LayoutMainBinding.inflate(layoutInflater)
        binding.fab.initProgress(binding.fabProgress)
        setupNavigationView()

        if (savedInstanceState == null) {
            displayFragmentWithId(R.id.nav_configuration)
        }
        setupBackNavigation()
        setupQuickActions()

        setContentView(binding.root)
        setupStartupUi()
        changeState(BaseService.State.Idle)
        setupRuntime()

        if (intent?.action == Intent.ACTION_VIEW) {
            onNewIntent(intent)
        }

        refreshNavMenu(DataStore.enableClashAPI)
        requestNotificationPermissionIfNeeded()

        if (isPreview) {
            MaterialAlertDialogBuilder(this)
                .setTitle(BuildConfig.PRE_VERSION_NAME)
                .setMessage(R.string.preview_version_hint)
                .setPositiveButton(android.R.string.ok, null)
                .show()
        }
    }

    private fun setupNavigationView() {
        if (themeResId !in intArrayOf(R.style.Theme_SagerNet_Black)) {
            navigation = binding.navView
            binding.drawerLayout.removeView(binding.navViewBlack)
        } else {
            navigation = binding.navViewBlack
            binding.drawerLayout.removeView(binding.navView)
        }
        navigation.setNavigationItemSelectedListener(this)
    }

    private fun setupBackNavigation() {
        onBackPressedDispatcher.addCallback {
            if (supportFragmentManager.findFragmentById(R.id.fragment_holder) is ConfigurationFragment) {
                moveTaskToBack(true)
            } else {
                displayFragmentWithId(R.id.nav_configuration)
            }
        }
    }

    private fun setupQuickActions() {
        binding.fab.setOnClickListener {
            if (DataStore.internalProxyActive && DataStore.serviceMode == Key.MODE_PROXY) {
                val restoreId = DataStore.internalProxyUserSelected
                if (restoreId > 0L) {
                    DataStore.selectedProxy = restoreId
                    DataStore.currentProfile = restoreId
                }
                DataStore.serviceMode = Key.MODE_VPN
                if (DataStore.serviceState.canStop) {
                    SagerNet.stopService()
                    pendingVpnStartJob?.cancel()
                    pendingVpnStartJob = lifecycleScope.launchWhenStarted {
                        val timeoutMs = 5_000L
                        val start = System.currentTimeMillis()
                        while (System.currentTimeMillis() - start < timeoutMs) {
                            if (DataStore.serviceState == BaseService.State.Stopped ||
                                DataStore.serviceState == BaseService.State.Idle
                            ) {
                                break
                            }
                            delay(100L)
                        }
                        DataStore.internalProxyActive = false
                        DataStore.internalProxyProfileId = 0L
                        launchConnectWithAutoFallback()
                    }
                } else {
                    DataStore.internalProxyActive = false
                    DataStore.internalProxyProfileId = 0L
                    launchConnectWithAutoFallback()
                }
            } else if (DataStore.serviceState.canStop) {
                SagerNet.stopService()
            } else {
                if (DataStore.clientMode && DataStore.serviceMode != Key.MODE_VPN) {
                    DataStore.serviceMode = Key.MODE_VPN
                }
                launchConnectWithAutoFallback()
            }
        }
        binding.stats.setOnClickListener(null)
        binding.locationCard.setOnClickListener {
            displayFragment(WebviewFragment(), true)
            navigation.menu.findItem(R.id.nav_singbox_dashboard)?.isChecked = true
        }
    }

    private fun setupStartupUi() {
        setupConnectEffectAlignment()
        if (!BuildConfig.DEBUG && DataStore.clientMode) {
            DataStore.clientMode = false
        }
        applyClientModeUi()
        animateEntrance()
    }

    private fun setupRuntime() {
        connection.connect(this, this)
        DataStore.configurationStore.registerChangeListener(this)
        GroupManager.userInterface = GroupInterfaceAdapter(this)
        GroupUpdater.listeners.add(updateProgressListener)
        applyConnectionPerformanceBaseline()
        runOnDefaultDispatcher {
            GroupManager.ensureDefaultSubscriptionGroup()
        }
        ensureDefaultAutoSelectOnFirstRun()
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < 33) return
        val checkPermission =
            ContextCompat.checkSelfPermission(this@MainActivity, POST_NOTIFICATIONS)
        if (checkPermission != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(
                this@MainActivity, arrayOf(POST_NOTIFICATIONS), 0
            )
        }
    }

    fun refreshNavMenu(clashApi: Boolean) {
        if (::navigation.isInitialized) {
            navigation.menu.findItem(R.id.nav_singbox_dashboard)?.isVisible = clashApi
            navigation.menu.findItem(R.id.nav_client_mode)?.apply {
                isVisible = BuildConfig.DEBUG
                isChecked = DataStore.clientMode
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)

        val uri = intent.data ?: return

        runOnDefaultDispatcher {
            importHandler.handleIntent(uri)
        }
    }

    suspend fun importSubscription(uri: Uri) {
        importHandler.importSubscription(uri)
    }

    suspend fun importProfile(uri: Uri) {
        importHandler.importProfile(uri)
    }

    override fun missingPlugin(profileName: String, pluginName: String) {
        val pluginEntity = PluginEntry.find(pluginName)

        // unknown exe or neko plugin
        if (pluginEntity == null) {
            snackbar(getString(R.string.plugin_unknown, pluginName)).show()
            return
        }

        // official exe

        MaterialAlertDialogBuilder(this).setTitle(R.string.missing_plugin)
            .setMessage(
                getString(
                    R.string.profile_requiring_plugin, profileName, pluginEntity.displayName
                )
            )
            .setPositiveButton(R.string.action_download) { _, _ ->
                showDownloadDialog(pluginEntity)
            }
            .setNeutralButton(android.R.string.cancel, null)
            .setNeutralButton(R.string.action_learn_more) { _, _ ->
                launchCustomTab("https://matsuridayo.github.io/nb4a-plugin/")
            }
            .show()
    }

    private fun showDownloadDialog(pluginEntry: PluginEntry) {
        var index = 0
        var playIndex = -1
        var fdroidIndex = -1

        val items = mutableListOf<String>()
        if (pluginEntry.downloadSource.playStore) {
            items.add(getString(R.string.install_from_play_store))
            playIndex = index++
        }
        if (pluginEntry.downloadSource.fdroid) {
            items.add(getString(R.string.install_from_fdroid))
            fdroidIndex = index++
        }

        items.add(getString(R.string.download))
        val downloadIndex = index

        MaterialAlertDialogBuilder(this).setTitle(pluginEntry.name)
            .setItems(items.toTypedArray()) { _, which ->
                when (which) {
                    playIndex -> launchCustomTab("https://play.google.com/store/apps/details?id=${pluginEntry.packageName}")
                    fdroidIndex -> launchCustomTab("https://f-droid.org/packages/${pluginEntry.packageName}/")
                    downloadIndex -> launchCustomTab(pluginEntry.downloadSource.downloadLink)
                }
            }
            .show()
    }

    override fun onNavigationItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.nav_client_mode -> {
                if (!BuildConfig.DEBUG) {
                    binding.drawerLayout.closeDrawers()
                    return true
                }
                DataStore.clientMode = !DataStore.clientMode
                item.isChecked = DataStore.clientMode
                applyClientModeUi()
                if (DataStore.clientMode) {
                    displayFragmentWithId(R.id.nav_configuration)
                }
                binding.drawerLayout.closeDrawers()
                true
            }
            else -> {
                if (item.isChecked) {
                    binding.drawerLayout.closeDrawers()
                    true
                } else {
                    displayFragmentWithId(item.itemId)
                }
            }
        }
    }


    @SuppressLint("CommitTransaction")
    fun displayFragment(fragment: Fragment) {
        displayFragment(fragment, false)
    }

    @SuppressLint("CommitTransaction")
    fun displayFragment(fragment: Fragment, animate: Boolean) {
        if (DataStore.clientMode) {
            binding.stats.visibility = View.GONE
            binding.fab.show()
        } else {
            if (fragment is ConfigurationFragment) {
                binding.stats.visibility = View.VISIBLE
                binding.fab.show()
            } else if (!DataStore.showBottomBar) {
                binding.stats.visibility = View.GONE
                binding.fab.hide()
            }
        }
        if (fragment is ConfigurationFragment && DataStore.serviceState == BaseService.State.Connected) {
            binding.locationFlag.text = "🌍"
            locationController.start()
        } else {
            locationController.stop()
        }
        val tx = supportFragmentManager.beginTransaction()
        if (animate) {
            tx.setCustomAnimations(
                android.R.anim.fade_in,
                android.R.anim.fade_out,
                android.R.anim.fade_in,
                android.R.anim.fade_out
            )
        }
        tx.replace(R.id.fragment_holder, fragment)
            .commitAllowingStateLoss()
        binding.drawerLayout.closeDrawers()
    }

    private fun applyClientModeUi() {
        val params = binding.fab.layoutParams as androidx.coordinatorlayout.widget.CoordinatorLayout.LayoutParams
        val progressParams = binding.fabProgress.layoutParams as androidx.coordinatorlayout.widget.CoordinatorLayout.LayoutParams
        val density = resources.displayMetrics.density
        if (::navigation.isInitialized) {
            navigation.menu.findItem(R.id.nav_client_mode)?.isChecked = DataStore.clientMode
        }
        (supportFragmentManager.findFragmentById(R.id.fragment_holder) as? ConfigurationFragment)
            ?.updateAddProfileMenuForClientMode()
        if (DataStore.clientMode) {
            enforceClientModeVpn(restartIfRunning = true)
            if (DataStore.internalProxyActive && DataStore.serviceMode == Key.MODE_PROXY) {
                DataStore.internalProxyActive = false
                DataStore.internalProxyProfileId = 0L
                DataStore.internalProxyUserSelected = 0L
                if (DataStore.serviceState.canStop) {
                    SagerNet.stopService()
                }
            }
            val margin = (20 * density).toInt()
            params.anchorGravity = Gravity.END or Gravity.BOTTOM
            params.marginEnd = margin
            params.bottomMargin = margin
            binding.fab.translationY = 0f
            binding.fab.customSize = (72 * density).toInt()
            progressParams.anchorGravity = Gravity.END or Gravity.BOTTOM
            progressParams.marginEnd = margin
            progressParams.bottomMargin = margin
            binding.fabProgress.indicatorSize = (110 * density).toInt()
            binding.connectGlow.visibility = View.GONE
            binding.stats.visibility = View.GONE
        } else {
            params.anchorGravity = Gravity.CENTER_HORIZONTAL or Gravity.CENTER_VERTICAL
            params.marginEnd = 0
            params.bottomMargin = 0
            binding.fab.translationY = 0f
            binding.fab.customSize = (204 * density).toInt()
            progressParams.anchorGravity = Gravity.CENTER
            progressParams.marginEnd = 0
            progressParams.bottomMargin = 0
            binding.fabProgress.indicatorSize = (270 * density).toInt()
            binding.connectGlow.visibility = View.VISIBLE
        }
        binding.fab.layoutParams = params
        binding.fabProgress.layoutParams = progressParams
    }



    private fun enforceClientModeVpn(restartIfRunning: Boolean) {
        if (!DataStore.clientMode) return
        if (DataStore.serviceMode == Key.MODE_VPN) return
        DataStore.serviceMode = Key.MODE_VPN
        if (!restartIfRunning || !DataStore.serviceState.canStop) return
        SagerNet.stopService()
        pendingVpnStartJob?.cancel()
        pendingVpnStartJob = lifecycleScope.launchWhenStarted {
            val timeoutMs = 5_000L
            val start = System.currentTimeMillis()
            while (System.currentTimeMillis() - start < timeoutMs) {
                if (DataStore.serviceState == BaseService.State.Stopped ||
                    DataStore.serviceState == BaseService.State.Idle
                ) {
                    break
                }
                delay(100L)
            }
            launchConnectWithAutoFallback()
        }
    }

    fun displayFragmentWithId(@IdRes id: Int): Boolean {
        when (id) {
            R.id.nav_configuration -> {
                displayFragment(ConfigurationFragment())
            }

            R.id.nav_group -> displayFragment(GroupFragment())
            R.id.nav_settings -> displayFragment(SettingsFragment())
            R.id.nav_singbox_dashboard -> {
                displayFragment(WebviewFragment())
                return false
            }
            R.id.nav_tools -> displayFragment(ToolsFragment())
            R.id.nav_logcat -> displayFragment(LogcatFragment())
            R.id.nav_internal_browser -> {
                startActivity(Intent(this, InternalBrowserActivity::class.java))
                return false
            }
            R.id.nav_about -> displayFragment(AboutFragment())

            else -> return false
        }
        navigation.menu.findItem(id)?.isChecked = true
        return true
    }

    private fun changeState(
        state: BaseService.State,
        msg: String? = null,
        animate: Boolean = false,
    ) {
        val previousState = DataStore.serviceState
        DataStore.serviceState = state

        val uiState = if (DataStore.internalProxyActive && DataStore.serviceMode == Key.MODE_PROXY) {
            BaseService.State.Stopped
        } else {
            state
        }
        val previousUiState = if (DataStore.internalProxyActive && DataStore.serviceMode == Key.MODE_PROXY) {
            BaseService.State.Stopped
        } else {
            previousState
        }
        binding.fab.changeState(uiState, previousUiState, animate)
        binding.stats.changeState(uiState)
        connectionAnimator.updateStateAnimation(uiState)
        updateStatsAnimation(uiState)
        if (uiState == BaseService.State.Connected) {
            locationController.start()
        } else {
            locationController.stop()
        }
        if (msg != null) snackbar(getString(R.string.vpn_error, msg)).show()
        if (state == BaseService.State.Stopped && !DataStore.clientMode) {
            scheduleInternalProxyRestart()
        }
        updateFabUpdateProgress()
    }

    private fun previewConnectingState() {
        val previousUiState = if (DataStore.internalProxyActive && DataStore.serviceMode == Key.MODE_PROXY) {
            BaseService.State.Stopped
        } else {
            DataStore.serviceState
        }
        binding.fab.changeState(BaseService.State.Connecting, previousUiState, true)
        binding.stats.changeState(BaseService.State.Connecting)
        connectionAnimator.updateStateAnimation(BaseService.State.Connecting)
        updateStatsAnimation(BaseService.State.Connecting)
        locationController.stop()
        updateFabUpdateProgress()
    }

    private fun updateFabUpdateProgress() {
        val active = GroupUpdater.updating.isNotEmpty()
        binding.fabProgress.isVisible = active
        if (!active) return
        val totalMax = GroupUpdater.progress.values.sumOf { it.max }
        val totalProgress = GroupUpdater.progress.values.sumOf { it.progress }
        if (totalMax <= 0) {
            binding.fabProgress.isIndeterminate = true
            return
        }
        binding.fabProgress.isIndeterminate = false
        binding.fabProgress.max = totalMax
        binding.fabProgress.progress = totalProgress.coerceAtMost(totalMax)
    }

    private fun scheduleInternalProxyRestart() {
        if (isFinishing || isDestroyed) return
        if (DataStore.clientMode) return
        if (DataStore.internalProxyActive) return
        internalProxyRestartJob?.cancel()
        internalProxyRestartJob = lifecycleScope.launchWhenStarted {
            delay(300L)
            if (isFinishing || isDestroyed) return@launchWhenStarted
            if (DataStore.serviceState != BaseService.State.Stopped) return@launchWhenStarted
            if (DataStore.internalProxyActive) return@launchWhenStarted
        }
    }

    private fun animateEntrance() {
        binding.fragmentHolder.apply {
            alpha = 0f
            animate().alpha(1f).setDuration(360L).setStartDelay(80L).start()
        }
        binding.stats.apply {
            alpha = 0f
            visibility = View.INVISIBLE
        }
        binding.fab.apply {
            alpha = 0f
            scaleX = 0.9f
            scaleY = 0.9f
            animate().alpha(1f).scaleX(1f).scaleY(1f).setDuration(420L).setStartDelay(120L).start()
        }
        binding.fabProgress.apply {
            alpha = 0f
            animate().alpha(1f).setDuration(420L).setStartDelay(140L).start()
        }
    }

    private fun setupConnectEffectAlignment() {
        binding.coordinator.addOnLayoutChangeListener { _, _, _, _, _, _, _, _, _ ->
            updateConnectEffectOffsets()
        }
        updateConnectEffectOffsets()
    }

    internal fun updateConnectEffectOffsets() {
        val fab = binding.fab
        if (fab.width == 0 || fab.height == 0) return
        val fabCenterX = fab.left + fab.translationX + fab.width / 2f
        val fabCenterY = fab.top + fab.translationY + fab.height / 2f
        val targets = arrayOf(
            binding.connectGlow,
            binding.connectRing,
            binding.connectRingSoft,
            binding.fabProgress
        )
        for (view in targets) {
            if (view.width == 0 || view.height == 0) continue
            val viewCenterX = view.left + view.width / 2f
            val viewCenterY = view.top + view.height / 2f
            view.translationX = fabCenterX - viewCenterX
            view.translationY = fabCenterY - viewCenterY
        }
    }

    private fun updateStatsAnimation(state: BaseService.State) {
        val stats = binding.stats
        stats.animate().cancel()
        if (state == BaseService.State.Connected) {
            val density = resources.displayMetrics.density
            stats.visibility = View.VISIBLE
            stats.alpha = 0f
            stats.scaleX = 0.92f
            stats.scaleY = 0.92f
            stats.translationY = 220f * density
            stats.animate()
                .alpha(1f)
                .scaleX(1f)
                .scaleY(1f)
                .translationY(156f * density)
                .setDuration(520L)
                .setInterpolator(OvershootInterpolator(0.9f))
                .setStartDelay(60L)
                .start()
        } else {
            stats.animate()
                .alpha(0f)
                .scaleX(0.9f)
                .scaleY(0.9f)
                .setDuration(220L)
                .withEndAction { stats.visibility = View.INVISIBLE }
                .start()
        }
    }


    private fun ensureDefaultAutoSelectOnFirstRun() {
        runOnDefaultDispatcher {
            val all = SagerDatabase.proxyDao.getAll()
            val auto = all.firstOrNull { GroupManager.isDefaultAutoSelectConfig(it) }
            val fallback = auto ?: all.firstOrNull()
            if (fallback == null) return@runOnDefaultDispatcher
            if (DataStore.internalProxyActive && DataStore.serviceMode == Key.MODE_PROXY) {
                val selected = DataStore.internalProxyUserSelected
                val selectedExists = selected > 0L && SagerDatabase.proxyDao.getById(selected) != null
                if (!selectedExists) {
                    DataStore.internalProxyUserSelected = fallback.id
                }
            } else {
                val selected = DataStore.selectedProxy
                val selectedExists = selected > 0L && SagerDatabase.proxyDao.getById(selected) != null
                if (!selectedExists) {
                    DataStore.selectedProxy = fallback.id
                    DataStore.currentProfile = fallback.id
                }
            }
        }
    }

    private fun launchConnectWithAutoFallback() {
        runOnDefaultDispatcher {
            val ok = ensureSelectedProxyForConnect()
            onMainDispatcher {
                if (ok) {
                    previewConnectingState()
                    connect.launch(null)
                } else {
                    snackbar(R.string.profile_empty).show()
                }
            }
        }
    }

    private fun applyConnectionPerformanceBaseline() {
        runOnDefaultDispatcher {
            val key = "perfBaselineV6Done"
            if (DataStore.configurationStore.getBoolean(key, false)) return@runOnDefaultDispatcher

            if (DataStore.parallelConcurrency < 16) DataStore.parallelConcurrency = 24
            if (DataStore.parallelDelayMs > 180) DataStore.parallelDelayMs = 120
            if (DataStore.parallelTimeoutMs < 5000) DataStore.parallelTimeoutMs = 8000
            if (DataStore.parallelIntervalSec > 60) DataStore.parallelIntervalSec = 20
            if (DataStore.parallelTolerance > 40) DataStore.parallelTolerance = 20
            if (DataStore.connectionTestConcurrent > 32 || DataStore.connectionTestConcurrent < 8) {
                DataStore.connectionTestConcurrent = 20
            }
            val oldParallelUrl = DataStore.parallelUrl.trim()
            if (
                oldParallelUrl.isBlank() ||
                oldParallelUrl == "https://cp.cloudflare.com/generate_204" ||
                oldParallelUrl == "http://cp.cloudflare.com/" ||
                oldParallelUrl == "https://www.gstatic.com/generate_204"
            ) {
                DataStore.parallelUrl = "https://speed.cloudflare.com/__down?bytes=1000000"
            }
            DataStore.autoSelectPrimary = "parallel"
            if (DataStore.smartSwitchCooldownSec < 30 || DataStore.smartSwitchCooldownSec > 90) {
                DataStore.smartSwitchCooldownSec = 45
            }
            if (DataStore.smartSwitchMinDwellSec < 30 || DataStore.smartSwitchMinDwellSec > 90) {
                DataStore.smartSwitchMinDwellSec = 45
            }
            if (DataStore.smartSwitchProbeIntervalSec < 12 || DataStore.smartSwitchProbeIntervalSec > 40) {
                DataStore.smartSwitchProbeIntervalSec = 20
            }
            if (DataStore.smartSwitchBadProbeIntervalSec < 4 || DataStore.smartSwitchBadProbeIntervalSec > 12) {
                DataStore.smartSwitchBadProbeIntervalSec = 6
            }
            if (DataStore.smartSwitchWarmupRounds < 2 || DataStore.smartSwitchWarmupRounds > 6) {
                DataStore.smartSwitchWarmupRounds = 3
            }
            if (DataStore.smartSwitchCandidateWins < 2 || DataStore.smartSwitchCandidateWins > 5) {
                DataStore.smartSwitchCandidateWins = 2
            }
            if (DataStore.smartSwitchCandidateWinsWarmup < 1 || DataStore.smartSwitchCandidateWinsWarmup > 4) {
                DataStore.smartSwitchCandidateWinsWarmup = 2
            }
            if (DataStore.smartSwitchMinImproveAbs < 150 || DataStore.smartSwitchMinImproveAbs > 600) {
                DataStore.smartSwitchMinImproveAbs = 260
            }
            if (DataStore.smartSwitchMinImprovePct < 10 || DataStore.smartSwitchMinImprovePct > 40) {
                DataStore.smartSwitchMinImprovePct = 20
            }
            if (DataStore.smartSwitchWeakScore < 800 || DataStore.smartSwitchWeakScore > 1800) {
                DataStore.smartSwitchWeakScore = 1100
            }
            if (DataStore.smartSwitchCriticalScore < 1000 || DataStore.smartSwitchCriticalScore > 2600) {
                DataStore.smartSwitchCriticalScore = 1500
            }
            if (DataStore.smartSwitchFailStreakTrigger < 1 || DataStore.smartSwitchFailStreakTrigger > 5) {
                DataStore.smartSwitchFailStreakTrigger = 2
            }
            if (DataStore.smartSwitchStableLockSec < 180 || DataStore.smartSwitchStableLockSec > 1200) {
                DataStore.smartSwitchStableLockSec = 300
            }
            if (DataStore.smartSwitchExcellentScore < 500 || DataStore.smartSwitchExcellentScore > 1200) {
                DataStore.smartSwitchExcellentScore = 760
            }
            if (DataStore.smartSwitchMinThroughputGainPct < 8 || DataStore.smartSwitchMinThroughputGainPct > 60) {
                DataStore.smartSwitchMinThroughputGainPct = 18
            }
            DataStore.configurationStore.putBoolean(key, true)
        }
    }

    private fun ensureSelectedProxyForConnect(): Boolean {
        val selected = DataStore.selectedProxy
        val selectedExists = selected > 0L && SagerDatabase.proxyDao.getById(selected) != null
        if (selectedExists) return true

        val all = SagerDatabase.proxyDao.getAll()
        val auto = all.firstOrNull { GroupManager.isDefaultAutoSelectConfig(it) }
        val fallback = auto ?: all.firstOrNull() ?: return false
        DataStore.selectedProxy = fallback.id
        DataStore.currentProfile = fallback.id
        return true
    }

    private suspend fun runFirstRunUpdate(defaultGroup: ProxyGroup?) {
        if (DataStore.firstRunDone) return
        if (defaultGroup == null) return
        val needsDefault = isGroupEmptyForFirstRun(defaultGroup)
        if (!needsDefault) return

        DataStore.firstRunSilentUpdateActive = true
        try {
            val okDefault = GroupUpdater.executeUpdate(defaultGroup, false)
            if (okDefault) {
                DataStore.firstRunDone = true
                onMainDispatcher {
                    snackbar(getString(R.string.first_run_update_success)).show()
                }
            }
        } finally {
            DataStore.firstRunSilentUpdateActive = false
        }
    }

    private fun isGroupEmptyForFirstRun(group: ProxyGroup): Boolean {
        val subscription = group.subscription ?: return false
        if (subscription.lastUpdated > 0) return false
        val proxies = SagerDatabase.proxyDao.getByGroup(group.id)
        val hasRealProxy = proxies.any { proxy ->
            when {
                GroupManager.isAutoSelectAggregate(proxy) -> false
                else -> true
            }
        }
        return !hasRealProxy
    }

    override fun snackbarInternal(text: CharSequence): Snackbar {
        return Snackbar.make(binding.coordinator, text, Snackbar.LENGTH_LONG).apply {
            if (binding.fab.isShown) {
                anchorView = binding.fab
            }
            // TODO
        }
    }

    override fun stateChanged(state: BaseService.State, profileName: String?, msg: String?) {
        changeState(state, msg, true)
    }

    val connection = SagerConnection(SagerConnection.CONNECTION_ID_MAIN_ACTIVITY_FOREGROUND, true)
    override fun onServiceConnected(service: ISagerNetService) = changeState(
        try {
            BaseService.State.values()[service.state]
        } catch (_: RemoteException) {
            BaseService.State.Idle
        }
    )

    override fun onServiceDisconnected() = changeState(BaseService.State.Idle)
    override fun onBinderDied() {
        connection.disconnect(this)
        connection.connect(this, this)
    }

    private val connect = registerForActivityResult(VpnRequestActivity.StartService()) {
        if (it) snackbar(R.string.vpn_permission_denied).show()
    }

    // may NOT called when app is in background
    // ONLY do UI update here, write DB in bg process
    override fun cbSpeedUpdate(stats: SpeedDisplayData) {
        binding.stats.updateSpeed(stats.txRateProxy, stats.rxRateProxy)
    }

    override fun cbTrafficUpdate(data: TrafficData) {
        runOnDefaultDispatcher {
            ProfileManager.postUpdate(data)
        }
    }

    override fun cbSelectorUpdate(id: Long) {
        val old = DataStore.selectedProxy
        DataStore.selectedProxy = id
        DataStore.currentProfile = id
        runOnDefaultDispatcher {
            ProfileManager.postUpdate(old, true)
            ProfileManager.postUpdate(id, true)
        }
    }

    override fun onPreferenceDataStoreChanged(store: PreferenceDataStore, key: String) {
        when (key) {
            Key.SERVICE_MODE -> onBinderDied()
            Key.PROXY_APPS, Key.BYPASS_MODE, Key.INDIVIDUAL -> {
                if (DataStore.serviceState.canStop) {
                    snackbar(getString(R.string.need_reload)).setAction(R.string.apply) {
                        SagerNet.reloadService()
                    }.show()
                }
            }
        }
    }

    override fun onStart() {
        connection.updateConnectionId(SagerConnection.CONNECTION_ID_MAIN_ACTIVITY_FOREGROUND)
        super.onStart()
    }

    override fun onStop() {
        connection.updateConnectionId(SagerConnection.CONNECTION_ID_MAIN_ACTIVITY_BACKGROUND)
        super.onStop()
    }

    override fun onDestroy() {
        super.onDestroy()
        connectionAnimator.release()
        GroupManager.userInterface = null
        GroupUpdater.listeners.remove(updateProgressListener)
        DataStore.configurationStore.unregisterChangeListener(this)
        connection.disconnect(this)
    }

    override fun onKeyDown(keyCode: Int, event: KeyEvent): Boolean {
        when (keyCode) {
            KeyEvent.KEYCODE_DPAD_LEFT -> {
                if (super.onKeyDown(keyCode, event)) return true
                binding.drawerLayout.open()
                navigation.requestFocus()
            }

            KeyEvent.KEYCODE_DPAD_RIGHT -> {
                if (binding.drawerLayout.isOpen) {
                    binding.drawerLayout.close()
                    return true
                }
            }
        }

        if (super.onKeyDown(keyCode, event)) return true
        if (binding.drawerLayout.isOpen) return false

        val fragment =
            supportFragmentManager.findFragmentById(R.id.fragment_holder) as? ToolbarFragment
        return fragment != null && fragment.onKeyDown(keyCode, event)
    }

}
