package io.nekohasekai.sagernet.ui

import android.annotation.SuppressLint
import android.os.Bundle
import android.view.View
import android.webkit.*
import android.widget.ProgressBar
import android.widget.TextView
import androidx.core.view.isVisible
import io.nekohasekai.sagernet.BuildConfig
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.utils.ClashApiClient
import moe.matsuri.nb4a.utils.WebViewUtil
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// Fragment必须有一个无参public的构造函数，否则在数据恢复的时候，会报crash

class WebviewFragment : Fragment(R.layout.layout_webview_fullscreen) {

    lateinit var mWebView: WebView
    private lateinit var statusView: View
    private lateinit var progress: ProgressBar
    private lateinit var statusTitle: TextView
    private lateinit var statusMessage: TextView
    private lateinit var retry: MaterialButton
    private var loadJob: Job? = null

    @SuppressLint("SetJavaScriptEnabled")
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // webview
        WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG)
        mWebView = view.findViewById(R.id.webview)
        statusView = view.findViewById(R.id.dashboard_status)
        progress = view.findViewById(R.id.dashboard_progress)
        statusTitle = view.findViewById(R.id.dashboard_status_title)
        statusMessage = view.findViewById(R.id.dashboard_status_message)
        retry = view.findViewById(R.id.dashboard_retry)
        mWebView.settings.domStorageEnabled = true
        mWebView.settings.javaScriptEnabled = true
        mWebView.settings.databaseEnabled = true
        mWebView.webViewClient = object : WebViewClient() {
            override fun onReceivedError(
                view: WebView?, request: WebResourceRequest?, error: WebResourceError?
            ) {
                WebViewUtil.onReceivedError(view, request, error)
                if (request?.isForMainFrame != false) {
                    showError(getString(R.string.dashboard_web_error))
                }
            }

            override fun onPageFinished(view: WebView?, url: String?) {
                super.onPageFinished(view, url)
                statusView.isVisible = false
            }
        }
        retry.setOnClickListener { loadDashboard() }
        loadDashboard()
    }

    override fun onDestroyView() {
        loadJob?.cancel()
        mWebView.stopLoading()
        super.onDestroyView()
    }

    private fun loadDashboard() {
        loadJob?.cancel()
        showLoading()
        loadJob = viewLifecycleOwner.lifecycleScope.launch {
            val ready = waitForDashboardApi()
            if (!ready) {
                showError(getString(R.string.dashboard_api_unavailable))
                return@launch
            }
            mWebView.loadUrl(DataStore.yacdURL)
        }
    }

    private fun showLoading() {
        statusView.isVisible = true
        progress.isVisible = true
        retry.isVisible = false
        statusTitle.setText(R.string.dashboard_loading)
        statusMessage.setText(R.string.dashboard_waiting_for_api)
    }

    private fun showError(message: String) {
        statusView.isVisible = true
        progress.isVisible = false
        retry.isVisible = true
        statusTitle.setText(R.string.menu_dashboard)
        statusMessage.text = message
    }

    private suspend fun waitForDashboardApi(): Boolean {
        repeat(API_CHECK_ATTEMPTS) {
            if (isDashboardApiReady()) return true
            delay(API_CHECK_DELAY_MS)
        }
        return false
    }

    private suspend fun isDashboardApiReady(): Boolean = withContext(Dispatchers.IO) {
        ClashApiClient().isReady()
    }

    private companion object {
        const val API_CHECK_ATTEMPTS = 10
        const val API_CHECK_DELAY_MS = 350L
    }
}
