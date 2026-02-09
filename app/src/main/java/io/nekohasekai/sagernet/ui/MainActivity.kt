package io.nekohasekai.sagernet.ui

import android.Manifest.permission.POST_NOTIFICATIONS
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.RemoteException
import android.animation.ObjectAnimator
import android.animation.PropertyValuesHolder
import android.animation.ValueAnimator
import android.animation.AnimatorSet
import android.animation.ArgbEvaluator
import android.view.Gravity
import android.view.KeyEvent
import android.view.MenuItem
import android.view.View
import android.graphics.drawable.GradientDrawable
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
import io.nekohasekai.sagernet.GroupType
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlin.math.max

class MainActivity : ThemedActivity(),
    SagerConnection.Callback,
    OnPreferenceDataStoreChangeListener,
    NavigationView.OnNavigationItemSelectedListener {

    lateinit var binding: LayoutMainBinding
    lateinit var navigation: NavigationView
    private var glowAnimator: ObjectAnimator? = null
    private var stateAnimator: ObjectAnimator? = null
    private var connectAnimator: AnimatorSet? = null
    private var ringAnimator: AnimatorSet? = null
    private var fabColorAnimator: ValueAnimator? = null
    private var ringSoftAnimator: AnimatorSet? = null
    private var ambientAnimator: ObjectAnimator? = null
    private var disconnectAnimating = false
    private var locationPollJob: Job? = null
    private var locationFetchInFlight = false
    private var lastLocationFlag: String? = null
    private var lastLocationFetchAt: Long = 0L
    private val updateProgressListener = object : GroupUpdater.Listener {
        override fun onProgressChanged() {
            runOnUiThread { updateFabUpdateProgress() }
        }
    }
    private var internalProxyRestartJob: Job? = null
    private var pendingVpnStartJob: Job? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = LayoutMainBinding.inflate(layoutInflater)
        binding.fab.initProgress(binding.fabProgress)
        if (themeResId !in intArrayOf(
                R.style.Theme_SagerNet_Black
            )
        ) {
            navigation = binding.navView
            binding.drawerLayout.removeView(binding.navViewBlack)
        } else {
            navigation = binding.navViewBlack
            binding.drawerLayout.removeView(binding.navView)
        }
        navigation.setNavigationItemSelectedListener(this)

        if (savedInstanceState == null) {
            displayFragmentWithId(R.id.nav_configuration)
        }
        onBackPressedDispatcher.addCallback {
            if (supportFragmentManager.findFragmentById(R.id.fragment_holder) is ConfigurationFragment) {
                moveTaskToBack(true)
            } else {
                displayFragmentWithId(R.id.nav_configuration)
            }
        }

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
                        connect.launch(null)
                    }
                } else {
                    DataStore.internalProxyActive = false
                    DataStore.internalProxyProfileId = 0L
                    connect.launch(null)
                }
            } else if (DataStore.serviceState.canStop) {
                SagerNet.stopService()
            } else {
                if (DataStore.clientMode && DataStore.serviceMode != Key.MODE_VPN) {
                    DataStore.serviceMode = Key.MODE_VPN
                }
                connect.launch(null)
            }
        }
        binding.stats.setOnClickListener(null)
        binding.locationCard.setOnClickListener {
            displayFragment(WebviewFragment(), true)
            navigation.menu.findItem(R.id.nav_singbox_dashboard)?.isChecked = true
        }

        setContentView(binding.root)
        setupConnectEffectAlignment()
        if (!BuildConfig.DEBUG && DataStore.clientMode) {
            DataStore.clientMode = false
        }
        applyClientModeUi()
        animateEntrance()
        changeState(BaseService.State.Idle)
        connection.connect(this, this)
        DataStore.configurationStore.registerChangeListener(this)
        GroupManager.userInterface = GroupInterfaceAdapter(this)
        GroupUpdater.listeners.add(updateProgressListener)
        runOnDefaultDispatcher {
            val defaultGroup = GroupManager.ensureDefaultSubscriptionGroup()
            runFirstRunUpdate(defaultGroup)
        }
        ensureDefaultAutoSelectOnFirstRun()
        runStartupServerCheck()

        if (intent?.action == Intent.ACTION_VIEW) {
            onNewIntent(intent)
        }

        refreshNavMenu(DataStore.enableClashAPI)

        // sdk 33 notification
        if (Build.VERSION.SDK_INT >= 33) {
            val checkPermission =
                ContextCompat.checkSelfPermission(this@MainActivity, POST_NOTIFICATIONS)
            if (checkPermission != PackageManager.PERMISSION_GRANTED) {
                //动态申请
                ActivityCompat.requestPermissions(
                    this@MainActivity, arrayOf(POST_NOTIFICATIONS), 0
                )
            }
        }

        if (isPreview) {
            MaterialAlertDialogBuilder(this)
                .setTitle(BuildConfig.PRE_VERSION_NAME)
                .setMessage(R.string.preview_version_hint)
                .setPositiveButton(android.R.string.ok, null)
                .show()
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
            if (uri.scheme == "sn" && uri.host == "subscription" || uri.scheme == "clash") {
                importSubscription(uri)
            } else {
                importProfile(uri)
            }
        }
    }


    suspend fun importSubscription(uri: Uri) {
        val group: ProxyGroup

        val url = uri.getQueryParameter("url")
        if (!url.isNullOrBlank()) {
            group = ProxyGroup(type = GroupType.SUBSCRIPTION)
            val subscription = SubscriptionBean()
            group.subscription = subscription

            // cleartext format
            subscription.link = url
            group.name = uri.getQueryParameter("name")
        } else {
            val data = uri.encodedQuery.takeIf { !it.isNullOrBlank() } ?: return
            try {
                group = KryoConverters.deserialize(
                    ProxyGroup().apply { export = true }, Util.zlibDecompress(Util.b64Decode(data))
                ).apply {
                    export = false
                }
            } catch (e: Exception) {
                onMainDispatcher {
                    alert(e.readableMessage).show()
                }
                return
            }
        }

        val name = group.name.takeIf { !it.isNullOrBlank() } ?: group.subscription?.link
        ?: group.subscription?.token
        if (name.isNullOrBlank()) return

        group.name = group.name.takeIf { !it.isNullOrBlank() }
            ?: ("Subscription #" + System.currentTimeMillis())

        onMainDispatcher {

            displayFragmentWithId(R.id.nav_group)

            MaterialAlertDialogBuilder(this@MainActivity).setTitle(R.string.subscription_import)
                .setMessage(getString(R.string.subscription_import_message, name))
                .setPositiveButton(R.string.yes) { _, _ ->
                    runOnDefaultDispatcher {
                        finishImportSubscription(group)
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()

        }

    }

    private suspend fun finishImportSubscription(subscription: ProxyGroup) {
        GroupManager.createGroup(subscription)
        GroupUpdater.startUpdate(subscription, true)
    }

    suspend fun importProfile(uri: Uri) {
        val profile = try {
            parseProxies(uri.toString()).getOrNull(0) ?: error(getString(R.string.no_proxies_found))
        } catch (e: Exception) {
            onMainDispatcher {
                alert(e.readableMessage).show()
            }
            return
        }

        onMainDispatcher {
            MaterialAlertDialogBuilder(this@MainActivity).setTitle(R.string.profile_import)
                .setMessage(getString(R.string.profile_import_message, profile.displayName()))
                .setPositiveButton(R.string.yes) { _, _ ->
                    runOnDefaultDispatcher {
                        finishImportProfile(profile)
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }

    }

    private suspend fun finishImportProfile(profile: AbstractBean) {
        val targetId = DataStore.selectedGroupForImport()

        ProfileManager.createProfile(targetId, profile)

        onMainDispatcher {
            displayFragmentWithId(R.id.nav_configuration)

            snackbar(resources.getQuantityString(R.plurals.added, 1, 1)).show()
        }
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
            binding.locationFlag.text = lastLocationFlag ?: "🌍"
            updateLocationCard()
        } else {
            updateLocationCard(forceHide = true)
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
            connect.launch(null)
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
        DataStore.serviceState = state

        val uiState = if (DataStore.internalProxyActive && DataStore.serviceMode == Key.MODE_PROXY) {
            BaseService.State.Stopped
        } else {
            state
        }
        binding.fab.changeState(uiState, DataStore.serviceState, animate)
        binding.stats.changeState(uiState)
        updateGlow(uiState)
        updateConnectAnimation(uiState)
        updateStateAnimation(uiState)
        updateStatsAnimation(uiState)
        if (uiState == BaseService.State.Connected) {
            startLocationPolling()
        } else {
            stopLocationPolling()
        }
        if (msg != null) snackbar(getString(R.string.vpn_error, msg)).show()
        if (state == BaseService.State.Stopped && !DataStore.clientMode) {
            scheduleInternalProxyRestart()
        }
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

    private fun updateConnectEffectOffsets() {
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

    private fun updateGlow(state: BaseService.State) {
        val glow = binding.connectGlow
        if (state == BaseService.State.Connected) {
            if (glowAnimator?.isRunning == true) return
            glow.visibility = View.VISIBLE
            glowAnimator?.cancel()
            glowAnimator = ObjectAnimator.ofPropertyValuesHolder(
                glow,
                PropertyValuesHolder.ofFloat(View.ALPHA, 0.35f, 0.15f),
                PropertyValuesHolder.ofFloat(View.SCALE_X, 1f, 1.08f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 1f, 1.08f)
            ).apply {
                duration = 1400L
                repeatMode = ValueAnimator.REVERSE
                repeatCount = ValueAnimator.INFINITE
                start()
            }
        } else {
            glowAnimator?.cancel()
            glowAnimator = null
            glow.alpha = 0f
            glow.scaleX = 1f
            glow.scaleY = 1f
            glow.visibility = View.INVISIBLE
        }
    }

    private fun updateConnectAnimation(state: BaseService.State) {
        connectAnimator?.cancel()
        connectAnimator = null
        ringAnimator?.cancel()
        ringAnimator = null
        ringSoftAnimator?.cancel()
        ringSoftAnimator = null
        ambientAnimator?.cancel()
        ambientAnimator = null
        fabColorAnimator?.cancel()
        fabColorAnimator = null

        if (state == BaseService.State.Connecting) {
            val density = resources.displayMetrics.density
            val fab = binding.fab
            val glow = binding.connectGlow
            val ring = binding.connectRing
            val ringSoft = binding.connectRingSoft
            val ambient = binding.connectAmbient
            val baseFabY = fab.translationY

            glow.visibility = View.VISIBLE
            glow.alpha = 0.2f
            glow.scaleX = 1f
            glow.scaleY = 1f

            ambient.visibility = View.VISIBLE
            ambient.alpha = 0.18f
            ambient.scaleX = 1f
            ambient.scaleY = 1f

            ring.visibility = View.VISIBLE
            ring.alpha = 0f
            ring.scaleX = 0.9f
            ring.scaleY = 0.9f

            ringSoft.visibility = View.VISIBLE
            ringSoft.alpha = 0f
            ringSoft.scaleX = 0.92f
            ringSoft.scaleY = 0.92f

            val glowPulse = ObjectAnimator.ofPropertyValuesHolder(
                glow,
                PropertyValuesHolder.ofFloat(View.ALPHA, 0.25f, 0.12f),
                PropertyValuesHolder.ofFloat(View.SCALE_X, 1f, 1.12f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 1f, 1.12f)
            ).apply {
                duration = 900L
                repeatMode = ValueAnimator.REVERSE
                repeatCount = ValueAnimator.INFINITE
            }

            val fabBreath = ObjectAnimator.ofPropertyValuesHolder(
                fab,
                PropertyValuesHolder.ofFloat(View.SCALE_X, 1f, 1.05f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 1f, 1.05f)
            ).apply {
                duration = 700L
                repeatMode = ValueAnimator.REVERSE
                repeatCount = ValueAnimator.INFINITE
            }

            val fabFloat = ObjectAnimator.ofFloat(
                fab,
                View.TRANSLATION_Y,
                baseFabY,
                baseFabY - (6f * density),
                baseFabY
            ).apply {
                duration = 1200L
                repeatMode = ValueAnimator.REVERSE
                repeatCount = ValueAnimator.INFINITE
                addUpdateListener { updateConnectEffectOffsets() }
            }

            connectAnimator = AnimatorSet().apply {
                playTogether(glowPulse, fabBreath, fabFloat)
                start()
            }

            val ringExpand = ObjectAnimator.ofPropertyValuesHolder(
                ring,
                PropertyValuesHolder.ofFloat(View.ALPHA, 0.0f, 0.22f, 0.0f),
                PropertyValuesHolder.ofFloat(View.SCALE_X, 0.86f, 1.18f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 0.86f, 1.18f)
            ).apply {
                duration = 2000L
                repeatCount = ValueAnimator.INFINITE
                repeatMode = ValueAnimator.RESTART
            }
            ringAnimator = AnimatorSet().apply {
                playTogether(ringExpand)
                start()
            }

            val ringSoftExpand = ObjectAnimator.ofPropertyValuesHolder(
                ringSoft,
                PropertyValuesHolder.ofFloat(View.ALPHA, 0.0f, 0.14f, 0.0f),
                PropertyValuesHolder.ofFloat(View.SCALE_X, 0.9f, 1.26f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 0.9f, 1.26f)
            ).apply {
                duration = 2600L
                startDelay = 320L
                repeatCount = ValueAnimator.INFINITE
                repeatMode = ValueAnimator.RESTART
            }
            ringSoftAnimator = AnimatorSet().apply {
                playTogether(ringSoftExpand)
                start()
            }

            setRingStrokeColor(
                ContextCompat.getColor(this, R.color.connect_ring),
                ContextCompat.getColor(this, R.color.connect_ring)
            )

            ambientAnimator = ObjectAnimator.ofPropertyValuesHolder(
                ambient,
                PropertyValuesHolder.ofFloat(View.ALPHA, 0.12f, 0.28f),
                PropertyValuesHolder.ofFloat(View.SCALE_X, 1f, 1.05f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 1f, 1.05f)
            ).apply {
                duration = 1600L
                repeatMode = ValueAnimator.REVERSE
                repeatCount = ValueAnimator.INFINITE
                start()
            }

            animateFabColor(
                ContextCompat.getColor(this, R.color.connect_fab_background),
                ContextCompat.getColor(this, R.color.connect_fab_background_connecting)
            )
        } else if (state == BaseService.State.Connected) {
            val ring = binding.connectRing
            val ringSoft = binding.connectRingSoft
            val ambient = binding.connectAmbient

            ring.visibility = View.VISIBLE
            ring.alpha = 0f
            ring.scaleX = 0.95f
            ring.scaleY = 0.95f

            ringSoft.visibility = View.VISIBLE
            ringSoft.alpha = 0f
            ringSoft.scaleX = 0.96f
            ringSoft.scaleY = 0.96f

            setRingStrokeColor(
                ContextCompat.getColor(this, R.color.connect_ring_connected),
                ContextCompat.getColor(this, R.color.connect_ring_connected)
            )

            val ringExpand = ObjectAnimator.ofPropertyValuesHolder(
                ring,
                PropertyValuesHolder.ofFloat(View.ALPHA, 0.0f, 0.18f, 0.0f),
                PropertyValuesHolder.ofFloat(View.SCALE_X, 0.9f, 1.2f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 0.9f, 1.2f)
            ).apply {
                duration = 2400L
                repeatCount = ValueAnimator.INFINITE
                repeatMode = ValueAnimator.RESTART
            }
            ringAnimator = AnimatorSet().apply {
                playTogether(ringExpand)
                start()
            }

            val ringSoftExpand = ObjectAnimator.ofPropertyValuesHolder(
                ringSoft,
                PropertyValuesHolder.ofFloat(View.ALPHA, 0.0f, 0.12f, 0.0f),
                PropertyValuesHolder.ofFloat(View.SCALE_X, 0.92f, 1.26f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 0.92f, 1.26f)
            ).apply {
                duration = 3200L
                startDelay = 360L
                repeatCount = ValueAnimator.INFINITE
                repeatMode = ValueAnimator.RESTART
            }
            ringSoftAnimator = AnimatorSet().apply {
                playTogether(ringSoftExpand)
                start()
            }

            ambient.visibility = View.VISIBLE
            ambient.alpha = 0.18f
            ambientAnimator = ObjectAnimator.ofPropertyValuesHolder(
                ambient,
                PropertyValuesHolder.ofFloat(View.ALPHA, 0.12f, 0.22f),
                PropertyValuesHolder.ofFloat(View.SCALE_X, 1f, 1.03f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 1f, 1.03f)
            ).apply {
                duration = 2200L
                repeatMode = ValueAnimator.REVERSE
                repeatCount = ValueAnimator.INFINITE
                start()
            }

            animateFabColor(
                ContextCompat.getColor(this, R.color.connect_fab_background_connecting),
                ContextCompat.getColor(this, R.color.connect_fab_background_connected)
            )
        } else {
            val ring = binding.connectRing
            val ringSoft = binding.connectRingSoft
            val ambient = binding.connectAmbient
            if (!disconnectAnimating) {
                ring.visibility = View.INVISIBLE
                ring.alpha = 0f
                ring.scaleX = 1f
                ring.scaleY = 1f
                ringSoft.visibility = View.INVISIBLE
                ringSoft.alpha = 0f
                ringSoft.scaleX = 1f
                ringSoft.scaleY = 1f
            }
            binding.fab.scaleX = 1f
            binding.fab.scaleY = 1f

            when (state) {
                BaseService.State.Stopping -> animateFabColor(
                    ContextCompat.getColor(this, R.color.connect_fab_background_connected),
                    ContextCompat.getColor(this, R.color.connect_fab_background_stopping),
                    800L
                )
                else -> animateFabColor(
                    ContextCompat.getColor(this, R.color.connect_fab_background_connected),
                    ContextCompat.getColor(this, R.color.connect_fab_background)
                )
            }

            when (state) {
                BaseService.State.Stopping -> {
                    playDisconnectCollapse()
                }
                else -> {
                    if (!disconnectAnimating) {
                        ambient.visibility = View.INVISIBLE
                        ambient.alpha = 0f
                    }
                }
            }
        }
    }

    private fun animateFabColor(fromColor: Int, toColor: Int, durationMs: Long = 420L) {
        fabColorAnimator?.cancel()
        fabColorAnimator = ValueAnimator.ofObject(ArgbEvaluator(), fromColor, toColor).apply {
            duration = durationMs
            addUpdateListener { animator ->
                val color = animator.animatedValue as Int
                binding.fab.backgroundTintList =
                    android.content.res.ColorStateList.valueOf(color)
            }
            start()
        }
    }

    private fun playDisconnectCollapse() {
        if (disconnectAnimating) return
        disconnectAnimating = true
        val ring = binding.connectRing
        val ringSoft = binding.connectRingSoft
        val ambient = binding.connectAmbient

        ring.visibility = View.VISIBLE
        ring.alpha = 0.26f
        ring.scaleX = 1.08f
        ring.scaleY = 1.08f

        ringSoft.visibility = View.VISIBLE
        ringSoft.alpha = 0.16f
        ringSoft.scaleX = 1.12f
        ringSoft.scaleY = 1.12f

        setRingStrokeColor(
            ContextCompat.getColor(this, R.color.connect_ring_disconnect),
            ContextCompat.getColor(this, R.color.connect_ring_disconnect)
        )

        val ringOut = ObjectAnimator.ofPropertyValuesHolder(
            ring,
            PropertyValuesHolder.ofFloat(View.ALPHA, 0.26f, 0f),
            PropertyValuesHolder.ofFloat(View.SCALE_X, 1.08f, 0.88f),
            PropertyValuesHolder.ofFloat(View.SCALE_Y, 1.08f, 0.88f)
        ).apply { duration = 3000L }

        val ringSoftOut = ObjectAnimator.ofPropertyValuesHolder(
            ringSoft,
            PropertyValuesHolder.ofFloat(View.ALPHA, 0.16f, 0f),
            PropertyValuesHolder.ofFloat(View.SCALE_X, 1.12f, 0.9f),
            PropertyValuesHolder.ofFloat(View.SCALE_Y, 1.12f, 0.9f)
        ).apply { duration = 3000L }

        val ambientFade = ObjectAnimator.ofFloat(ambient, View.ALPHA, ambient.alpha, 0f).apply {
            duration = 3000L
        }

        AnimatorSet().apply {
            playTogether(ringOut, ringSoftOut, ambientFade)
            addListener(object : android.animation.AnimatorListenerAdapter() {
                override fun onAnimationEnd(animation: android.animation.Animator) {
                    ring.visibility = View.INVISIBLE
                    ringSoft.visibility = View.INVISIBLE
                    ambient.visibility = View.INVISIBLE
                    disconnectAnimating = false
                }
            })
            start()
        }
    }

    private fun setRingStrokeColor(ringColor: Int, ringSoftColor: Int) {
        val ring = binding.connectRing.background as? GradientDrawable
        val ringSoft = binding.connectRingSoft.background as? GradientDrawable
        val density = resources.displayMetrics.density
        val ringStroke = (2f * density).toInt()
        val ringSoftStroke = (1f * density).toInt()
        ring?.setStroke(ringStroke, ringColor)
        ringSoft?.setStroke(ringSoftStroke, ringSoftColor)
    }

    private fun updateStateAnimation(state: BaseService.State) {
        stateAnimator?.cancel()
        stateAnimator = null
        when (state) {
            BaseService.State.Connecting -> {
                stateAnimator = ObjectAnimator.ofPropertyValuesHolder(
                    binding.fragmentHolder,
                    PropertyValuesHolder.ofFloat(View.SCALE_X, 1f, 1.01f),
                    PropertyValuesHolder.ofFloat(View.SCALE_Y, 1f, 1.01f)
                ).apply {
                    duration = 1200L
                    repeatMode = ValueAnimator.REVERSE
                    repeatCount = ValueAnimator.INFINITE
                    start()
                }
            }
            BaseService.State.Stopping -> {
                val fab = binding.fab
                fab.animate().cancel()
                stateAnimator = ObjectAnimator.ofPropertyValuesHolder(
                    binding.fragmentHolder,
                    PropertyValuesHolder.ofFloat(View.ALPHA, 1f, 0.9f, 1f)
                ).apply {
                    duration = 360L
                    repeatCount = 0
                    start()
                }
                fab.animate()
                    .scaleX(0.96f)
                    .scaleY(0.96f)
                    .setDuration(180L)
                    .withEndAction {
                        fab.animate().scaleX(1f).scaleY(1f).setDuration(220L).start()
                    }
                    .start()
            }
            else -> {
                binding.fragmentHolder.scaleX = 1f
                binding.fragmentHolder.scaleY = 1f
                binding.fragmentHolder.alpha = 1f
            }
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
            val auto = all.firstOrNull { GroupManager.isDefaultAutoSelectConfig(it) } ?: return@runOnDefaultDispatcher
            if (DataStore.internalProxyActive && DataStore.serviceMode == Key.MODE_PROXY) {
                if (DataStore.internalProxyUserSelected == 0L) {
                    DataStore.internalProxyUserSelected = auto.id
                }
            } else {
                if (DataStore.selectedProxy == 0L) {
                    DataStore.selectedProxy = auto.id
                    DataStore.currentProfile = auto.id
                }
            }
        }
    }

    private fun runStartupServerCheck() {
        binding.startupLoading.isVisible = true
        binding.startupLoading.post {
            binding.startupLoading.bringToFront()
            binding.startupLoading.alpha = 1f
        }
        binding.startupLoadingProgress.isIndeterminate = true
        binding.startupLoadingText.setText(R.string.startup_checking_servers)
        runOnDefaultDispatcher {
            val startMs = System.currentTimeMillis()
            val group = GroupManager.ensureDefaultSubscriptionGroup()
            val subscription = group?.subscription
            val needsUpdate = if (subscription == null) {
                false
            } else {
                val lastUpdated = subscription.lastUpdated ?: 0
                val delayMin = subscription.autoUpdateDelay ?: 1440
                val elapsedSec = (System.currentTimeMillis() / 1000).toInt() - lastUpdated
                lastUpdated == 0 || elapsedSec >= delayMin * 60
            }
            if (group != null && needsUpdate) {
                onMainDispatcher {
                    binding.startupLoadingText.setText(R.string.startup_updating_servers)
                }
                GroupUpdater.executeUpdate(group, false)
            }
            val elapsed = System.currentTimeMillis() - startMs
            val remaining = max(0L, 4000L - elapsed)
            if (remaining > 0L) {
                delay(remaining)
            }
            onMainDispatcher {
                binding.startupLoading.isVisible = false
            }
        }
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

    private fun startLocationPolling() {
        locationPollJob?.cancel()
        locationPollJob = lifecycleScope.launchWhenStarted {
            while (true) {
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
                    updateLocationCard(forceHide = true)
                }
                delay(5000L)
            }
        }
    }

    private fun stopLocationPolling() {
        locationPollJob?.cancel()
        locationPollJob = null
        locationFetchInFlight = false
        lastLocationFlag = null
        lastLocationFetchAt = 0L
        updateLocationCard(forceHide = true)
    }

    private fun isOnMainScreen(): Boolean {
        return supportFragmentManager.findFragmentById(R.id.fragment_holder) is ConfigurationFragment
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
        }.getOrNull()
    }

    private fun countryCodeToFlag(code: String): String {
        val upper = code.uppercase(Locale.US)
        val first = 0x1F1E6 + (upper[0] - 'A')
        val second = 0x1F1E6 + (upper[1] - 'A')
        return String(Character.toChars(first)) + String(Character.toChars(second))
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
