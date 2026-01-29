package io.nekohasekai.sagernet.widget

import android.content.Context
import android.text.format.Formatter
import android.util.AttributeSet
import android.widget.LinearLayout
import android.widget.TextView
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.bg.BaseService

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
        txText.text = "↑ ${Formatter.formatFileSize(context, txRate)}/s"
        rxText.text = "↓ ${Formatter.formatFileSize(context, rxRate)}/s"
    }
}
