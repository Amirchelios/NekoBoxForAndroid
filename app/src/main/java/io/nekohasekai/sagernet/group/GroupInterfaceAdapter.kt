package io.nekohasekai.sagernet.group

import com.google.android.material.dialog.MaterialAlertDialogBuilder
import androidx.core.content.ContextCompat
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.GroupManager
import io.nekohasekai.sagernet.database.ProxyGroup
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import io.nekohasekai.sagernet.ktx.runOnMainDispatcher
import io.nekohasekai.sagernet.ui.ThemedActivity
import kotlinx.coroutines.delay
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

class GroupInterfaceAdapter(val context: ThemedActivity) : GroupManager.Interface {

    private val summaryTargets = setOf(
        SagerNet.application.getString(R.string.menu_auto_select)
    )
    private val pendingSummary = LinkedHashMap<String, Boolean>()
    private val pendingErrors = LinkedHashMap<String, String>()
    private var summaryScheduled = false

    override suspend fun confirm(message: String): Boolean {
        return suspendCoroutine {
            runOnMainDispatcher {
                MaterialAlertDialogBuilder(context).setTitle(R.string.confirm)
                    .setMessage(message)
                    .setPositiveButton(R.string.yes) { _, _ -> it.resume(true) }
                    .setNegativeButton(R.string.no) { _, _ -> it.resume(false) }
                    .setOnCancelListener { _ -> it.resume(false) }
                    .show()
            }
        }
    }

    override suspend fun alert(message: String) {
        return suspendCoroutine {
            runOnMainDispatcher {
                MaterialAlertDialogBuilder(context).setTitle(R.string.ooc_warning)
                    .setMessage(message)
                    .setPositiveButton(android.R.string.ok) { _, _ -> it.resume(Unit) }
                    .setOnCancelListener { _ -> it.resume(Unit) }
                    .show()
            }
        }
    }

    private suspend fun recordSummary(group: ProxyGroup, success: Boolean, error: String = "") {
        val name = group.displayName()
        if (!summaryTargets.contains(name)) return
        pendingSummary[name] = success
        if (!success && error.isNotBlank()) {
            pendingErrors[name] = error
        }
        if (pendingSummary.size < summaryTargets.size) return
        showSummary()
    }

    private suspend fun showSummary() {
        val successLabel = context.getString(R.string.update_status_success)
        val failedLabel = context.getString(R.string.update_status_failed)
        val lines = summaryTargets.mapNotNull { target ->
            val ok = pendingSummary[target] ?: return@mapNotNull null
            val label = if (ok) successLabel else failedLabel
            val extra = if (!ok) {
                pendingErrors[target]?.let { "\n${it}" }.orEmpty()
            } else ""
            context.getString(R.string.update_status_line, target, label) + extra
        }
        pendingSummary.clear()
        pendingErrors.clear()
        summaryScheduled = false
        onMainDispatcher {
            val allSuccess = lines.all { it.contains(successLabel) }
            val snackbar = context.snackbar(
                context.getString(R.string.update_summary_title) + "\n" + lines.joinToString("\n")
            )
            snackbar.view.setBackgroundColor(
                ContextCompat.getColor(
                    context,
                    if (allSuccess) R.color.material_green_500 else R.color.material_red_500
                )
            )
            snackbar.show()
        }
    }

    override suspend fun onUpdateSuccess(
        group: ProxyGroup,
        changed: Int,
        added: List<String>,
        updated: Map<String, String>,
        deleted: List<String>,
        duplicate: List<String>,
        byUser: Boolean
    ) {
        GroupUpdater.markUpdateSuccess(group.id)
        if (DataStore.firstRunSilentUpdateActive) {
            return
        }
        recordSummary(group, true)
        if (!summaryScheduled) {
            summaryScheduled = true
            onMainDispatcher {
                delay(1500L)
                if (pendingSummary.isNotEmpty()) {
                    showSummary()
                }
            }
        }
    }

    override suspend fun onUpdateFailure(group: ProxyGroup, message: String) {
        GroupUpdater.markUpdateFailure(group.id)
        if (DataStore.firstRunSilentUpdateActive) {
            return
        }
        recordSummary(group, false, message)
        if (!summaryScheduled) {
            summaryScheduled = true
            onMainDispatcher {
                delay(1500L)
                if (pendingSummary.isNotEmpty()) {
                    showSummary()
                }
            }
        }
    }

}
