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
        txText.text = formatSpeed(txRate)
        rxText.text = formatSpeed(rxRate)
    }

    private fun formatSpeed(rate: Long): String {
        return "${Formatter.formatFileSize(context, rate).toEnglishDigits()}/s"
    }

    private fun String.toEnglishDigits(): String {
        val map = mapOf(
            '۰' to '0', '۱' to '1', '۲' to '2', '۳' to '3', '۴' to '4',
            '۵' to '5', '۶' to '6', '۷' to '7', '۸' to '8', '۹' to '9',
            '٠' to '0', '١' to '1', '٢' to '2', '٣' to '3', '٤' to '4',
            '٥' to '5', '٦' to '6', '٧' to '7', '٨' to '8', '٩' to '9'
        )
        val sb = StringBuilder(length)
        for (ch in this) {
            sb.append(map[ch] ?: ch)
        }
        return sb.toString()
    }
}
