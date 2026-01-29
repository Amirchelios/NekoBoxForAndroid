package io.nekohasekai.sagernet.ui

import android.annotation.SuppressLint
import android.os.Bundle
import android.text.InputType
import android.view.inputmethod.EditorInfo
import android.webkit.WebResourceRequest
import android.webkit.WebResourceError
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
import io.nekohasekai.sagernet.databinding.LayoutWebviewBinding
import moe.matsuri.nb4a.utils.WebViewUtil

class InternalBrowserActivity : ThemedActivity(), Toolbar.OnMenuItemClickListener {

    private lateinit var binding: LayoutWebviewBinding
    private lateinit var webView: WebView
    private val homeUrl = "file:///android_asset/browser_home.html"

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = LayoutWebviewBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        toolbar.setTitle(R.string.menu_browser)
        toolbar.inflateMenu(R.menu.browser_menu)
        toolbar.setOnMenuItemClickListener(this)
        toolbar.setNavigationIcon(R.drawable.ic_navigation_close)
        toolbar.setNavigationOnClickListener { finish() }

        webView = binding.webview
        webView.settings.domStorageEnabled = true
        webView.settings.javaScriptEnabled = true
        webView.webViewClient = object : WebViewClient() {
            override fun onReceivedError(
                view: WebView?, request: WebResourceRequest?, error: WebResourceError?
            ) {
                WebViewUtil.onReceivedError(view, request, error)
            }

            override fun onPageFinished(view: WebView?, url: String?) {
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
        binding.addressInput.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_GO) {
                navigateFromInput()
                true
            } else {
                false
            }
        }

        applyProxyForWebView()
        if (DataStore.internalBrowserUrl.isBlank()) {
            DataStore.internalBrowserUrl = homeUrl
        }
        webView.loadUrl(DataStore.internalBrowserUrl)
    }

    override fun onDestroy() {
        if (WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
            ProxyController.getInstance().clearProxyOverride(
                ContextCompat.getMainExecutor(this)
            ) {}
        }
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
}
