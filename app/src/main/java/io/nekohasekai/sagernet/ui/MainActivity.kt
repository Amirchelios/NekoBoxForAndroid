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
import android.view.Gravity
import android.view.KeyEvent
import android.view.MenuItem
import android.view.View
import androidx.activity.addCallback
import androidx.annotation.IdRes
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
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
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay

class MainActivity : ThemedActivity(),
    SagerConnection.Callback,
    OnPreferenceDataStoreChangeListener,
    NavigationView.OnNavigationItemSelectedListener {

    lateinit var binding: LayoutMainBinding
    lateinit var navigation: NavigationView
    private var glowAnimator: ObjectAnimator? = null
    private var stateAnimator: ObjectAnimator? = null
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

        setContentView(binding.root)
        applyClientModeUi()
        animateEntrance()
        changeState(BaseService.State.Idle)
        connection.connect(this, this)
        DataStore.configurationStore.registerChangeListener(this)
        GroupManager.userInterface = GroupInterfaceAdapter(this)
        runOnDefaultDispatcher {
            GroupManager.ensureDefaultSubscriptionGroup()
            GroupManager.ensureDedicatedSubscriptionGroup()
        }
        ensureDefaultAutoSelectOnFirstRun()
        ensureInternalProxyOnAppStart()

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
            navigation.menu.findItem(R.id.nav_client_mode)?.isChecked = DataStore.clientMode
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
    fun displayFragment(fragment: ToolbarFragment) {
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
        supportFragmentManager.beginTransaction()
            .replace(R.id.fragment_holder, fragment)
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
            binding.fab.translationY = 48 * density
            binding.fab.customSize = (136 * density).toInt()
            progressParams.anchorGravity = Gravity.CENTER
            progressParams.marginEnd = 0
            progressParams.bottomMargin = 0
            binding.fabProgress.indicatorSize = (180 * density).toInt()
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
            R.id.nav_route -> displayFragment(RouteFragment())
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
        navigation.menu.findItem(id).isChecked = true
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
        updateStateAnimation(uiState)
        updateStatsAnimation(uiState)
        if (msg != null) snackbar(getString(R.string.vpn_error, msg)).show()
        if (state == BaseService.State.Stopped && !DataStore.clientMode) {
            scheduleInternalProxyRestart()
        }
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
            ensureInternalProxyOnAppStart()
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
                stateAnimator = ObjectAnimator.ofPropertyValuesHolder(
                    binding.fragmentHolder,
                    PropertyValuesHolder.ofFloat(View.ALPHA, 1f, 0.9f, 1f)
                ).apply {
                    duration = 360L
                    repeatCount = 0
                    start()
                }
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
            stats.visibility = View.VISIBLE
            stats.alpha = 0f
            stats.scaleX = 0.9f
            stats.scaleY = 0.9f
            stats.translationY = 196f
            stats.animate()
                .alpha(1f)
                .scaleX(1f)
                .scaleY(1f)
                .translationY(156f)
                .setDuration(420L)
                .setStartDelay(80L)
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

    private fun ensureInternalProxyOnAppStart() {
        runOnDefaultDispatcher {
            if (DataStore.clientMode) return@runOnDefaultDispatcher
            if (DataStore.internalProxyActive || DataStore.serviceState.connected) return@runOnDefaultDispatcher
            val all = SagerDatabase.proxyDao.getAll()
            var dedicated = all.firstOrNull { GroupManager.isDedicatedConfig(it) }
            var reachable = false
            if (dedicated != null) {
                reachable = GroupUpdater.testDedicatedReachable(dedicated)
            }
            if (!reachable) {
                val fetched = GroupUpdater.autoFetchDedicatedConfig(5000L)
                if (fetched) {
                    val refreshed = SagerDatabase.proxyDao.getAll()
                    dedicated = refreshed.firstOrNull { GroupManager.isDedicatedConfig(it) }
                    if (dedicated != null) {
                        reachable = GroupUpdater.testDedicatedReachable(dedicated)
                    }
                }
            }
            if (!reachable || dedicated == null) return@runOnDefaultDispatcher

            if (DataStore.internalProxyUserSelected == 0L) {
                DataStore.internalProxyUserSelected = DataStore.selectedProxy
            }
            DataStore.internalProxyProfileId = dedicated.id
            DataStore.internalProxyActive = true
            DataStore.selectedProxy = dedicated.id
            DataStore.currentProfile = dedicated.id
            DataStore.serviceMode = Key.MODE_PROXY
            SagerNet.startService()
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
        GroupManager.userInterface = null
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
