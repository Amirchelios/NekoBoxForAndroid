package io.nekohasekai.sagernet.ui

import android.annotation.SuppressLint
import android.app.DownloadManager
import android.content.BroadcastReceiver
import android.content.ContentValues
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.os.Bundle
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.text.InputType
import android.view.inputmethod.EditorInfo
import android.webkit.CookieManager
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
import androidx.webkit.ProxyConfig
import androidx.webkit.ProxyController
import androidx.webkit.WebViewFeature
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.GroupManager
import io.nekohasekai.sagernet.database.ProfileManager
import io.nekohasekai.sagernet.group.RawUpdater
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.SubscriptionFoundException
import io.nekohasekai.sagernet.ktx.USER_AGENT
import io.nekohasekai.sagernet.ktx.applyDefaultValues
import io.nekohasekai.sagernet.ktx.runOnMainDispatcher
import io.nekohasekai.sagernet.ktx.readableMessage
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import libcore.Libcore
import io.nekohasekai.sagernet.databinding.LayoutWebviewBinding
import moe.matsuri.nb4a.converter.ProxyToSingboxConverter
import moe.matsuri.nb4a.proxy.config.ConfigBean
import moe.matsuri.nb4a.utils.Util
import moe.matsuri.nb4a.utils.WebViewUtil
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.File
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlinx.coroutines.delay

class InternalBrowserActivity : ThemedActivity(), Toolbar.OnMenuItemClickListener {

    private lateinit var binding: LayoutWebviewBinding
    private lateinit var webView: WebView
    private val homeUrl = "file:///android_asset/browser_home.html"
    private var allowSelectAllClick = false
    private var targetGroupId: Long = 0L
    private var disableProxy = false
    private var pendingInitialUrl: String? = null
    private val unsafeHttp by lazy { buildUnsafeHttpClient() }
    private var downloadTriggered = false
    private var downloadInProgress = false
    private var lastLogFile: File? = null
    private var downloadManager: DownloadManager? = null
    private var downloadManagerId: Long = -1L
    private var downloadLogFile: File? = null
    private val downloadReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: android.content.Context?, intent: Intent?) {
            if (intent?.action != DownloadManager.ACTION_DOWNLOAD_COMPLETE) return
            val id = intent.getLongExtra(DownloadManager.EXTRA_DOWNLOAD_ID, -1L)
            if (id <= 0L || id != downloadManagerId) return
            handleDownloadManagerComplete(id)
        }
    }

    companion object {
        const val EXTRA_TARGET_GROUP_ID = "targetGroupId"
        const val EXTRA_INITIAL_URL = "initialUrl"
        const val EXTRA_DISABLE_PROXY = "disableProxy"
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = LayoutWebviewBinding.inflate(layoutInflater)
        setContentView(binding.root)
        targetGroupId = intent?.getLongExtra(EXTRA_TARGET_GROUP_ID, 0L) ?: 0L
        disableProxy = intent?.getBooleanExtra(EXTRA_DISABLE_PROXY, false) == true
        downloadManager = getSystemService(DOWNLOAD_SERVICE) as? DownloadManager
        val filter = IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(downloadReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(downloadReceiver, filter)
        }

        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        toolbar.setTitle(R.string.menu_browser)
        toolbar.inflateMenu(R.menu.browser_menu)
        toolbar.setOnMenuItemClickListener(this)
        toolbar.setNavigationIcon(R.drawable.ic_navigation_close)
        toolbar.setNavigationOnClickListener { finish() }

        webView = binding.webview
        webView.settings.domStorageEnabled = true
        webView.settings.javaScriptEnabled = true
        webView.settings.userAgentString = android.webkit.WebSettings.getDefaultUserAgent(this)
        CookieManager.getInstance().setAcceptCookie(true)
        webView.setDownloadListener { url, _, _, _, _ ->
            if (!url.isNullOrBlank() && !downloadInProgress) {
                if (shouldUseDownloadManager(url)) {
                    startDownloadManager(url)
                } else {
                    downloadAndImport(url)
                }
            }
        }
        webView.webViewClient = object : WebViewClient() {
            override fun onReceivedError(
                view: WebView?, request: WebResourceRequest?, error: WebResourceError?
            ) {
                WebViewUtil.onReceivedError(view, request, error)
            }

            override fun onPageFinished(view: WebView?, url: String?) {
                if (!downloadTriggered && !downloadInProgress) {
                    val current = url.orEmpty()
                    if (current.contains("link.txt")) {
                        downloadTriggered = true
                        if (shouldUseDownloadManager(current)) {
                            startDownloadManager(current)
                        } else {
                            downloadAndImport(current)
                        }
                    }
                    if (current.contains("drive.google.com/file/d/", true)) {
                        downloadTriggered = true
                        val direct = normalizeDownloadUrl(current)
                        if (shouldUseDownloadManager(direct)) {
                            startDownloadManager(direct)
                        } else {
                            downloadAndImport(direct)
                        }
                    }
                }
                if (url == homeUrl) {
                    binding.addressInput.setText("")
                } else {
                    binding.addressInput.setText(url ?: "")
                }
            }
        }

        binding.addressHome.setOnClickListener {
            DataStore.internalBrowserUrl = homeUrl
            webView.loadUrl(homeUrl)
        }
        binding.addressGo.setOnClickListener { navigateFromInput() }
        binding.addressHide.setOnClickListener { setAddressBarVisible(false) }
        binding.addressShow.setOnClickListener { setAddressBarVisible(true) }
        binding.addressInput.setOnFocusChangeListener { _, hasFocus ->
            if (hasFocus) {
                binding.addressInput.selectAll()
                allowSelectAllClick = true
            } else {
                allowSelectAllClick = false
            }
        }
        binding.addressInput.setOnClickListener {
            if (allowSelectAllClick) {
                binding.addressInput.selectAll()
                allowSelectAllClick = false
            }
        }
        binding.addressInput.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_GO) {
                navigateFromInput()
                true
            } else {
                false
            }
        }

        val initialUrl = intent?.getStringExtra(EXTRA_INITIAL_URL)?.trim().orEmpty()
        DataStore.internalBrowserUrl = when {
            initialUrl.isNotBlank() -> initialUrl
            DataStore.internalBrowserUrl.isBlank() -> homeUrl
            else -> DataStore.internalBrowserUrl
        }
        pendingInitialUrl = DataStore.internalBrowserUrl
        applyProxyAndLoad()
    }

    override fun onResume() {
        super.onResume()
        applyProxyAndLoad()
    }

    private fun applyProxyAndLoad() {
        val url = pendingInitialUrl
        if (disableProxy) {
            if (WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
                ProxyController.getInstance().clearProxyOverride(
                    ContextCompat.getMainExecutor(this)
                ) {
                    if (url != null) {
                        pendingInitialUrl = null
                        webView.loadUrl(url)
                    }
                }
            } else {
                if (url != null) {
                    pendingInitialUrl = null
                    webView.loadUrl(url)
                }
            }
        } else {
            applyProxyForWebView()
            if (url != null) {
                pendingInitialUrl = null
                webView.loadUrl(url)
            }
        }
    }

    override fun onDestroy() {
        if (WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
            ProxyController.getInstance().clearProxyOverride(
                ContextCompat.getMainExecutor(this)
            ) {}
        }
        runCatching { unregisterReceiver(downloadReceiver) }
        super.onDestroy()
    }

    override fun onMenuItemClick(item: android.view.MenuItem): Boolean {
        when (item.itemId) {
            R.id.action_set_url -> {
                val view = EditText(this).apply {
                    inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
                    setText(webView.url ?: DataStore.internalBrowserUrl)
                }
                MaterialAlertDialogBuilder(this)
                    .setTitle(R.string.set_browser_url)
                    .setView(view)
                    .setPositiveButton(android.R.string.ok) { _, _ ->
                        val url = view.text.toString().trim()
                        if (url.isNotBlank()) {
                            DataStore.internalBrowserUrl = url
                            webView.loadUrl(url)
                        }
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
            R.id.action_refresh -> webView.reload()
            R.id.action_export_log -> {
                val file = lastLogFile
                if (file != null && file.exists()) {
                    exportLogToDownloads(file)
                } else {
                    Toast.makeText(this, R.string.dedicated_link_import_failed, Toast.LENGTH_LONG).show()
                }
            }
        }
        return true
    }

    override fun onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack()
        } else {
            super.onBackPressed()
        }
    }

    private fun applyProxyForWebView() {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
            Toast.makeText(this, R.string.browser_proxy_unsupported, Toast.LENGTH_LONG).show()
            return
        }
        if (!DataStore.serviceState.started || !DataStore.serviceState.connected) {
            ProxyController.getInstance().clearProxyOverride(
                ContextCompat.getMainExecutor(this)
            ) {}
            return
        }
        val proxyConfig = ProxyConfig.Builder()
            .addProxyRule("socks://127.0.0.1:${DataStore.mixedPort}")
            .build()
        ProxyController.getInstance().setProxyOverride(
            proxyConfig,
            ContextCompat.getMainExecutor(this)
        ) {}
    }

    private fun navigateFromInput() {
        val input = binding.addressInput.text?.toString()?.trim().orEmpty()
        if (input.isBlank()) return
        val url = resolveInputToUrl(input)
        DataStore.internalBrowserUrl = url
        webView.loadUrl(url)
    }

    private fun resolveInputToUrl(input: String): String {
        val lowered = input.lowercase()
        if (lowered.startsWith("http://") || lowered.startsWith("https://")) return input
        if (lowered.contains("://")) return input
        if (input.contains(" ") || (!input.contains(".") && !input.contains(":") && input != "localhost")) {
            val query = android.net.Uri.encode(input)
            return "https://duckduckgo.com/?q=$query"
        }
        return "https://$input"
    }

    private fun setAddressBarVisible(visible: Boolean) {
        binding.addressBar.visibility = if (visible) android.view.View.VISIBLE else android.view.View.GONE
        binding.addressReveal.visibility = if (visible) android.view.View.GONE else android.view.View.VISIBLE
    }

    private fun shouldUseDownloadManager(url: String): Boolean {
        val normalized = normalizeDownloadUrl(url)
        return normalized.contains("drive.google.com/uc", true)
    }

    private fun createLogFile(): File {
        val diagnostics = File(getExternalFilesDir(null), "downloads").apply { mkdirs() }
        val logFile = File(diagnostics, "dedicated_import.log")
        lastLogFile = logFile
        return logFile
    }

    private fun appendLog(logFile: File, msg: String) {
        val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
        logFile.appendText("[$ts] $msg\n")
        Logs.d(msg)
    }

    private fun downloadAndImport(url: String) {
        downloadInProgress = true
        runOnDefaultDispatcher {
            val logFile = createLogFile()
            fun log(msg: String) = appendLog(logFile, msg)
            try {
                val normalizedUrl = normalizeDownloadUrl(url)
                runOnMainDispatcher {
                    Toast.makeText(this@InternalBrowserActivity, R.string.dedicated_link_downloading, Toast.LENGTH_SHORT).show()
                }
                log("Download start: $normalizedUrl, disableProxy=$disableProxy")
                val content = fetchContent(normalizedUrl, ::log)
                val downloadsDir = File(getExternalFilesDir(null), "downloads").apply { mkdirs() }
                val outputFile = File(downloadsDir, "link.txt")
                outputFile.writeText(content)
                processDownloadedContent(content, ::log)
            } catch (e: SubscriptionFoundException) {
                runOnMainDispatcher {
                    Toast.makeText(this@InternalBrowserActivity, e.readableMessage, Toast.LENGTH_LONG).show()
                }
                log("Import failed: ${e.readableMessage}")
                exportLogToDownloads(logFile)
            } catch (e: Exception) {
                Logs.w(e)
                runOnMainDispatcher {
                    Toast.makeText(this@InternalBrowserActivity, e.readableMessage, Toast.LENGTH_LONG).show()
                }
                log("Import failed: ${e.readableMessage}")
                exportLogToDownloads(logFile)
            } finally {
                downloadInProgress = false
            }
        }
    }

    private fun startDownloadManager(url: String) {
        if (downloadInProgress) return
        downloadInProgress = true
        val logFile = createLogFile()
        downloadLogFile = logFile
        fun log(msg: String) = appendLog(logFile, msg)
        val normalizedUrl = normalizeDownloadUrl(url)
        val manager = downloadManager
        if (manager == null) {
            log("DownloadManager unavailable, fallback to OkHttp")
            downloadInProgress = false
            downloadAndImport(normalizedUrl)
            return
        }
        runOnMainDispatcher {
            Toast.makeText(this@InternalBrowserActivity, R.string.dedicated_link_downloading, Toast.LENGTH_SHORT).show()
        }
        log("DownloadManager start: $normalizedUrl, disableProxy=$disableProxy")
        val request = DownloadManager.Request(Uri.parse(normalizedUrl))
            .setTitle("link.txt")
            .setDescription(getString(R.string.dedicated_link_downloading))
            .setAllowedOverMetered(true)
            .setAllowedOverRoaming(true)
        request.setAllowedNetworkTypes(
            DownloadManager.Request.NETWORK_WIFI or DownloadManager.Request.NETWORK_MOBILE
        )
            .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE)
        val ua = DataStore.subscriptionUserAgent.ifBlank { USER_AGENT }
        request.addRequestHeader("User-Agent", ua)
        request.addRequestHeader("Accept", "text/plain,*/*;q=0.9")
        request.addRequestHeader("Referer", normalizedUrl)
        val cookie = CookieManager.getInstance().getCookie(normalizedUrl)
        if (!cookie.isNullOrBlank()) {
            request.addRequestHeader("Cookie", cookie)
        }
        val fileName = "link_${System.currentTimeMillis()}.txt"
        request.setDestinationInExternalFilesDir(this, Environment.DIRECTORY_DOWNLOADS, fileName)
        downloadManagerId = runCatching { manager.enqueue(request) }.getOrElse {
            log("DownloadManager enqueue failed: ${it.message}")
            -1L
        }
        if (downloadManagerId <= 0L) {
            downloadInProgress = false
            downloadAndImport(normalizedUrl)
        } else {
            runOnDefaultDispatcher {
                pollDownloadManager(downloadManagerId, logFile, normalizedUrl)
            }
        }
    }

    private suspend fun pollDownloadManager(id: Long, logFile: File, normalizedUrl: String) {
        val manager = downloadManager ?: return
        fun log(msg: String) = appendLog(logFile, msg)
        var lastStatus = -1
        repeat(60) {
            val query = DownloadManager.Query().setFilterById(id)
            val cursor = manager.query(query)
            cursor?.use {
                if (it.moveToFirst()) {
                    val status = it.getInt(it.getColumnIndexOrThrow(DownloadManager.COLUMN_STATUS))
                    if (status != lastStatus) {
                        val reason = it.getInt(it.getColumnIndexOrThrow(DownloadManager.COLUMN_REASON))
                        val totalBytes = it.getLong(it.getColumnIndexOrThrow(DownloadManager.COLUMN_TOTAL_SIZE_BYTES))
                        val downloadedBytes = it.getLong(it.getColumnIndexOrThrow(DownloadManager.COLUMN_BYTES_DOWNLOADED_SO_FAR))
                        log("DownloadManager poll: status=$status reason=$reason bytes=$downloadedBytes/$totalBytes")
                        lastStatus = status
                        if (status == DownloadManager.STATUS_PAUSED &&
                            (reason == DownloadManager.PAUSED_WAITING_FOR_NETWORK ||
                                reason == DownloadManager.PAUSED_WAITING_TO_RETRY ||
                                reason == DownloadManager.PAUSED_QUEUED_FOR_WIFI)
                        ) {
                            log("DownloadManager paused, fallback to OkHttp")
                            runCatching { manager.remove(id) }
                            downloadManagerId = -1L
                            downloadInProgress = false
                            log("Fallback start: $normalizedUrl")
                            downloadAndImport(normalizedUrl)
                            return
                        }
                    }
                    if (status == DownloadManager.STATUS_SUCCESSFUL) {
                        handleDownloadManagerComplete(id)
                        return
                    }
                    if (status == DownloadManager.STATUS_FAILED) {
                        log("DownloadManager poll failed")
                        runCatching { manager.remove(id) }
                        exportLogToDownloads(logFile)
                        downloadManagerId = -1L
                        downloadInProgress = false
                        log("Fallback start: $normalizedUrl")
                        downloadAndImport(normalizedUrl)
                        return
                    }
                }
            }
            delay(1000)
        }
        log("DownloadManager poll timeout")
        exportLogToDownloads(logFile)
        runCatching { manager.remove(id) }
        downloadManagerId = -1L
        downloadInProgress = false
        log("Fallback start: $normalizedUrl")
        downloadAndImport(normalizedUrl)
    }

    private fun handleDownloadManagerComplete(id: Long) {
        val manager = downloadManager ?: return
        val logFile = downloadLogFile ?: createLogFile()
        fun log(msg: String) = appendLog(logFile, msg)
        runOnDefaultDispatcher {
            log("DownloadManager complete received: id=$id")
            val query = DownloadManager.Query().setFilterById(id)
            val cursor = manager.query(query)
            cursor?.use {
                if (!it.moveToFirst()) {
                    log("DownloadManager result missing")
                    downloadInProgress = false
                    return@runOnDefaultDispatcher
                }
                val status = it.getInt(it.getColumnIndexOrThrow(DownloadManager.COLUMN_STATUS))
                val reason = it.getInt(it.getColumnIndexOrThrow(DownloadManager.COLUMN_REASON))
                val totalBytes = it.getLong(it.getColumnIndexOrThrow(DownloadManager.COLUMN_TOTAL_SIZE_BYTES))
                val downloadedBytes = it.getLong(it.getColumnIndexOrThrow(DownloadManager.COLUMN_BYTES_DOWNLOADED_SO_FAR))
                val mediaType = it.getString(it.getColumnIndexOrThrow(DownloadManager.COLUMN_MEDIA_TYPE))
                val localUri = it.getString(it.getColumnIndexOrThrow(DownloadManager.COLUMN_LOCAL_URI))
                log("DownloadManager status=$status reason=$reason bytes=$downloadedBytes/$totalBytes type=$mediaType uri=$localUri")
                if (status != DownloadManager.STATUS_SUCCESSFUL) {
                    log("DownloadManager failed")
                    exportLogToDownloads(logFile)
                    downloadInProgress = false
                    return@runOnDefaultDispatcher
                }
                if (localUri.isNullOrBlank()) {
                    log("DownloadManager missing local uri")
                    exportLogToDownloads(logFile)
                    downloadInProgress = false
                    return@runOnDefaultDispatcher
                }
                val content = readDownloadedContent(localUri)
                if (content.isBlank()) {
                    log("Downloaded content empty")
                    exportLogToDownloads(logFile)
                    downloadInProgress = false
                    return@runOnDefaultDispatcher
                }
                try {
                    processDownloadedContent(content, ::log)
                } catch (e: Exception) {
                    log("Process failed: ${e.readableMessage}")
                    exportLogToDownloads(logFile)
                } finally {
                    downloadInProgress = false
                }
            }
        }
    }

    private fun readDownloadedContent(localUri: String): String {
        return runCatching {
            val uri = Uri.parse(localUri)
            if (uri.scheme == "content") {
                contentResolver.openInputStream(uri)?.use { stream ->
                    stream.bufferedReader().use { it.readText() }
                }.orEmpty()
            } else {
                val path = uri.path ?: localUri
                File(path).readText()
            }
        }.getOrElse {
            lastLogFile?.let { file ->
                appendLog(file, "Read downloaded content failed: ${it.message}")
            }
            ""
        }
    }

    private suspend fun processDownloadedContent(content: String, log: (String) -> Unit) {
        log("Downloaded bytes: ${content.length}")
        val downloadsDir = File(getExternalFilesDir(null), "downloads").apply { mkdirs() }
        val outputFile = File(downloadsDir, "link.txt")
        outputFile.writeText(content)
        runOnMainDispatcher { showDownloadedContent(content) }

        val payload = sanitizeLinkPayload(content)
        var results = RawUpdater.parseRaw(payload)
        if (results.isNullOrEmpty()) {
            val extracted = Regex("(vmess|vless|trojan|ss|hysteria2|hy2|hysteria|tuic|anytls)://[^\\s\"'>]+")
                .findAll(payload)
                .map { sanitizeLinkPayload(it.value) }
                .filter { it.isNotBlank() }
                .joinToString("\n")
            if (extracted.isNotBlank()) {
                log("Extracted links: ${extracted.lines().size}")
                results = RawUpdater.parseRaw(extracted)
            }
        }
        if (results.isNullOrEmpty()) {
            val singboxJson = ProxyToSingboxConverter.convertToSingBoxJson(payload).orEmpty()
            if (singboxJson.isNotBlank()) {
                val groupId = if (targetGroupId > 0L) {
                    targetGroupId
                } else {
                    GroupManager.ensureDedicatedSubscriptionGroup()?.id ?: 0L
                }
                if (groupId == 0L) {
                    runOnMainDispatcher {
                        Toast.makeText(this@InternalBrowserActivity, R.string.dedicated_link_import_failed, Toast.LENGTH_LONG).show()
                    }
                    log("Parse failed: no groupId for sing-box fallback")
                    return
                }
                val bean = ConfigBean().applyDefaultValues().apply {
                    type = 0
                    config = singboxJson
                    name = GroupManager.DEDICATED_CONFIG_NAME
                }
                ProfileManager.createProfile(groupId, bean)
                runOnMainDispatcher {
                    Toast.makeText(this@InternalBrowserActivity, R.string.dedicated_link_import_success, Toast.LENGTH_LONG).show()
                }
                log("Import via sing-box fallback")
                return
            }
            runOnMainDispatcher {
                Toast.makeText(this@InternalBrowserActivity, R.string.dedicated_link_import_failed, Toast.LENGTH_LONG).show()
            }
            log("Parse failed: no valid links found")
            return
        }

        val groupId = if (targetGroupId > 0L) {
            targetGroupId
        } else {
            GroupManager.ensureDedicatedSubscriptionGroup()?.id ?: 0L
        }
        if (groupId == 0L) {
            runOnMainDispatcher {
                Toast.makeText(this@InternalBrowserActivity, R.string.dedicated_link_import_failed, Toast.LENGTH_LONG).show()
            }
            return
        }
        for (profile in results) {
            ProfileManager.createProfile(groupId, profile)
        }
        runOnMainDispatcher {
            Toast.makeText(this@InternalBrowserActivity, R.string.dedicated_link_import_success, Toast.LENGTH_LONG).show()
        }
        log("Import success: ${results.size} profile(s), groupId=$groupId")
    }

    private fun exportLogToDownloads(logFile: File) {
        runOnMainDispatcher {
            runCatching {
                val resolver = contentResolver
                val fileName = "dedicated_import_${System.currentTimeMillis()}.log"
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, fileName)
                    put(MediaStore.Downloads.MIME_TYPE, "text/plain")
                    put(MediaStore.Downloads.IS_PENDING, 1)
                }
                val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) ?: return@runCatching
                resolver.openOutputStream(uri)?.use { out ->
                    logFile.inputStream().use { it.copyTo(out) }
                }
                values.clear()
                values.put(MediaStore.Downloads.IS_PENDING, 0)
                resolver.update(uri, values, null, null)
                Toast.makeText(this@InternalBrowserActivity, "Log saved: $fileName", Toast.LENGTH_LONG).show()
            }.onFailure {
                Toast.makeText(this@InternalBrowserActivity, "Log export failed: ${it.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun fetchContent(url: String, log: (String) -> Unit): String {
        fun requestWithOkHttp(target: String, referer: String? = null): String {
            val httpUrl = target.toHttpUrl()
            val request = Request.Builder()
                .url(httpUrl)
                .header("User-Agent", DataStore.subscriptionUserAgent.ifBlank { USER_AGENT })
                .header("Accept", "text/plain,*/*;q=0.9")
                .header("Referer", referer ?: target)
                .build()
            val response = unsafeHttp.newCall(request).execute()
            response.use { resp ->
                val body = resp.body?.string().orEmpty()
                if (body.isBlank()) {
                    log("OkHttp empty body, code=${resp.code}")
                }
                return body
            }
        }

        fun requestWithLibcore(target: String): String {
            val response = Libcore.newHttpClient().apply {
                if (!disableProxy) {
                    trySocks5(DataStore.mixedPort)
                }
            }.newRequest().apply {
                setURL(target)
                setUserAgent(DataStore.subscriptionUserAgent.ifBlank { USER_AGENT })
                allowInsecure()
            }.execute()
            return Util.getStringBox(response.contentString)
        }

        val first = runCatching { requestWithOkHttp(url) }.getOrElse {
            log("OkHttp failed: ${it.message}")
            requestWithLibcore(url)
        }
        if (!first.contains("<html", ignoreCase = true)) return first
        val extracted = extractDownloadUrl(first, url)
        if (extracted.isNullOrBlank()) {
            val normalized = normalizeDownloadUrl(url)
            if (!normalized.equals(url, ignoreCase = true)) {
                log("HTML received; trying normalized url: $normalized")
                return runCatching { requestWithOkHttp(normalized, url) }.getOrElse {
                    log("Normalized fetch failed: ${it.message}")
                    requestWithLibcore(normalized)
                }
            }
            log("HTML received but no download url found")
            return first
        }
        log("HTML redirect to: $extracted")
        return runCatching { requestWithOkHttp(extracted, url) }.getOrElse {
            log("OkHttp redirect failed: ${it.message}")
            requestWithLibcore(extracted)
        }
    }

    private fun normalizeDownloadUrl(raw: String): String {
        val url = raw.trim()
        val regex = Regex("""https?://[^\s"'<>]+""", RegexOption.IGNORE_CASE)
        regex.find(url)?.let { return it.value }
        val decoded = runCatching {
            URLDecoder.decode(url, StandardCharsets.UTF_8.name())
        }.getOrDefault(url)
        val shareMatch = Regex("""https?://t(elegram)?\.me/share/url\?url=([^&]+)""", RegexOption.IGNORE_CASE)
            .find(decoded)?.groupValues?.get(2)
        if (!shareMatch.isNullOrBlank()) return URLDecoder.decode(shareMatch, StandardCharsets.UTF_8.name())
        val driveId = Regex("""https?://drive\.google\.com/file/d/([^/]+)/?""", RegexOption.IGNORE_CASE)
            .find(decoded)?.groupValues?.get(1)
        if (!driveId.isNullOrBlank()) {
            return "https://drive.google.com/uc?export=download&id=$driveId"
        }
        val driveUc = Regex("""https?://drive\.google\.com/uc\?[^\\s"'<>]+""", RegexOption.IGNORE_CASE)
            .find(decoded)?.value
        if (!driveUc.isNullOrBlank()) return driveUc
        regex.find(decoded)?.let { return it.value }
        return url
    }

    private fun extractDownloadUrl(html: String, baseUrl: String): String? {
        val candidates = Regex("""href=["']([^"']+)["']""", RegexOption.IGNORE_CASE)
            .findAll(html)
            .map { it.groupValues[1] }
            .toList()
        val filtered = candidates.filterNot { it.contains("telegram.me/share/url", true) }
        val directTxt = filtered.firstOrNull { it.contains("link.txt") }
            ?: filtered.firstOrNull { it.endsWith(".txt") }
            ?: Regex("""https?://[^\s"'<>]+\.txt""", RegexOption.IGNORE_CASE).find(html)?.value
        if (!directTxt.isNullOrBlank()) {
            return try {
                val base = java.net.URI(baseUrl)
                resolvePicofileDirect(base.resolve(directTxt).toString())
            } catch (_: Exception) {
                resolvePicofileDirect(directTxt)
            }
        }

        // Meta refresh redirect
        val metaRefresh = Regex("""http-equiv=["']refresh["']\s+content=["'][^;]+;\s*url=([^"']+)["']""", RegexOption.IGNORE_CASE)
            .find(html)?.groupValues?.get(1)
        if (!metaRefresh.isNullOrBlank()) {
            return try {
                val base = java.net.URI(baseUrl)
                resolvePicofileDirect(base.resolve(metaRefresh).toString())
            } catch (_: Exception) {
                resolvePicofileDirect(metaRefresh)
            }
        }

        // JS-embedded URL with escaped slashes
        val escapedUrl = Regex("""https?:\\\\/\\\\/[^"'\\s<>]+""", RegexOption.IGNORE_CASE)
            .find(html)?.value
        if (!escapedUrl.isNullOrBlank()) {
            val unescaped = escapedUrl.replace("\\/", "/")
            if (unescaped.contains(".txt")) return unescaped
        }

        val downloadLink = Regex("""(data-href|data-url|data-link|data-clipboard-text|data-download|data-download-url|data-direct)=["']([^"']+)["']""", RegexOption.IGNORE_CASE)
            .find(html)?.groupValues?.get(2)
            ?: Regex("""https?://[^\s"'<>]+/dl\?[^"'<>]+""", RegexOption.IGNORE_CASE).find(html)?.value
            ?: Regex("""https?://drive\.google\.com/uc\?[^"'<>]+""", RegexOption.IGNORE_CASE)
                .find(html)?.value
        if (downloadLink.isNullOrBlank()) return null
        return try {
            val base = java.net.URI(baseUrl)
            resolvePicofileDirect(base.resolve(downloadLink).toString())
        } catch (_: Exception) {
            resolvePicofileDirect(downloadLink)
        }
    }

    private fun resolvePicofileDirect(url: String): String {
        var cleaned = normalizeDownloadUrl(url)
        // Telegram share wrapper -> extract real url, then keep processing
        val telegram = Regex("""https?://t(elegram)?\.me/share/url\?url=([^&]+)""", RegexOption.IGNORE_CASE)
            .find(cleaned)?.groupValues?.get(2)
        if (!telegram.isNullOrBlank()) {
            cleaned = URLDecoder.decode(telegram, StandardCharsets.UTF_8.name())
        }
        if (cleaned.endsWith(".txt.html")) {
            cleaned = cleaned.removeSuffix(".html")
        }
        // Convert /file/.../*.txt.html -> /d/.../*.txt
        if (cleaned.contains("/file/")) {
            val filePattern = Regex("""https?://[^/]+/file/([0-9]+)/([^/]+)""", RegexOption.IGNORE_CASE)
            val m = filePattern.find(cleaned)
            if (m != null) {
                val id = m.groupValues[1]
                val name = m.groupValues[2]
                return "https://s34.picofile.com/d/$id/$name"
            }
            return cleaned
        }
        val filePattern = Regex("""https?://[^/]+/file/([0-9]+)/([^/]+)""", RegexOption.IGNORE_CASE)
        val m = filePattern.find(cleaned)
        if (m != null) {
            val id = m.groupValues[1]
            val name = m.groupValues[2]
            return "https://s34.picofile.com/d/$id/$name"
        }
        return cleaned
    }

    private fun buildPicofileFilePageUrl(url: String): String? = null

    private fun buildUnsafeHttpClient(): OkHttpClient {
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf<TrustManager>(trustAll), SecureRandom())
        val sslSocketFactory = sslContext.socketFactory
        return OkHttpClient.Builder()
            .followRedirects(true)
            .followSslRedirects(true)
            .sslSocketFactory(sslSocketFactory, trustAll)
            .hostnameVerifier(HostnameVerifier { _, _ -> true })
            .cookieJar(WebViewCookieJar())
            .build()
    }

    private class WebViewCookieJar : CookieJar {
        private val manager = CookieManager.getInstance()

        override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
            cookies.forEach { manager.setCookie(url.toString(), it.toString()) }
        }

        override fun loadForRequest(url: HttpUrl): List<Cookie> {
            val cookieStr = manager.getCookie(url.toString()) ?: return emptyList()
            return cookieStr.split(";")
                .mapNotNull { Cookie.parse(url, it.trim()) }
        }
    }

    private fun sanitizeLinkPayload(raw: String): String {
        if (raw.isBlank()) return raw
        val decoded = runCatching {
            URLDecoder.decode(raw.trim(), StandardCharsets.UTF_8.name())
        }.getOrDefault(raw.trim())
        return decoded
            .replace(Regex("[?&]spx=[^&]*"), "")
            .replace(Regex("[?&]pqv=[^&]*"), "")
            .trim()
    }

    private fun showDownloadedContent(content: String) {
        val preview = if (content.length > 4000) {
            content.take(4000) + "\n\n...(truncated)..."
        } else {
            content
        }
        MaterialAlertDialogBuilder(this)
            .setTitle("link.txt")
            .setMessage(preview)
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }
}
