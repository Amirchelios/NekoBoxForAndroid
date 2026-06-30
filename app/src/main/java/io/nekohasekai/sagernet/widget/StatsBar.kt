package io.nekohasekai.sagernet.widget

import android.content.Context
import android.util.AttributeSet
import android.widget.LinearLayout
import android.widget.TextView
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.bg.BaseService
import java.util.Locale

class StatsBar @JvmOverloads constructor(
    context: Context, attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : LinearLayout(context, attrs, defStyleAttr) {
    private lateinit var txText: TextView
    private lateinit var rxText: TextView

    fun changeState(state: BaseService.State) {
        if (!this::txText.isInitialized) {
            txText = findViewById(R.id.tx)
            rxText = findViewById(R.id.rx)
        }
        if (state == BaseService.State.Connected) {
            alpha = 1f
        } else {
            alpha = 0.6f
            updateSpeed(0, 0)
        }
    }

    fun updateSpeed(txRate: Long, rxRate: Long) {
        if (!this::txText.isInitialized) {
            txText = findViewById(R.id.tx)
            rxText = findViewById(R.id.rx)
        }
        txText.text = formatSpeed(txRate)
        rxText.text = formatSpeed(rxRate)
    }

    private fun formatSpeed(rate: Long): String {
        val units = arrayOf("B", "KB", "MB", "GB", "TB")
        var value = rate.coerceAtLeast(0L).toDouble()
        var unit = 0
        while (value >= 1024.0 && unit < units.lastIndex) {
            value /= 1024.0
            unit++
        }
        val text = if (value >= 10.0 || unit == 0) {
            String.format(Locale.US, "%.0f", value)
        } else {
            String.format(Locale.US, "%.1f", value)
        }
        return "$text ${units[unit]}/s"
    }
}
