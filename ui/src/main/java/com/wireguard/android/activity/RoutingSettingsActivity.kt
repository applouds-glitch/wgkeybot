/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.activity

import android.content.Context
import android.content.DialogInterface
import android.os.Bundle
import android.util.Log
import android.util.Patterns
import android.view.LayoutInflater
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.isVisible
import androidx.core.view.updatePadding
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.wireguard.android.Application
import com.wireguard.android.R
import com.wireguard.android.databinding.RoutingSettingsActivityBinding
import com.wireguard.android.databinding.ViewWgkSettingsRowBinding
import com.wireguard.android.tether.TetherManager
import com.wireguard.android.tether.TetherRouting
import com.wireguard.android.tether.TetherSettings
import com.wireguard.android.tether.formatRoutingDate
import com.wireguard.android.tether.formatTetherBytes
import com.wireguard.android.util.applicationScope
import com.wireguard.android.util.localeWrapped
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.atomic.AtomicInteger

private const val TAG = "WireGuard/RoutingSettings"

/**
 * Where the split-routing rules come from and what is on disk: the profile
 * address, the resolver for direct destinations, the files' versions, and the
 * button that fetches them now rather than at the next start.
 *
 * Both edits and the update apply to a running sharing session through
 * [TetherManager.reloadRouting], which restarts the native proxy under the
 * access point: clients stay joined, their connections reopen.
 */
class RoutingSettingsActivity : AppCompatActivity() {

    override fun attachBaseContext(newBase: Context) = super.attachBaseContext(newBase.localeWrapped())

    private lateinit var binding: RoutingSettingsActivityBinding

    /**
     * The edit dialog, held so it can be taken down with the activity. A dialog
     * left showing through a recreation is a leaked window and a leaked context,
     * and its save lambda would then write into a dead binding.
     */
    private var dialog: AlertDialog? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        binding = RoutingSettingsActivityBinding.inflate(layoutInflater)
        setContentView(binding.root)
        applyInsets()
        binding.wgkRoutingToolbar.setNavigationOnClickListener { finish() }

        binding.wgkRoutingUrlRow.apply {
            wgkRowIcon.setImageResource(R.drawable.ic_cloud)
            wgkRowLabel.setText(R.string.wgk_routing_url_label)
            wgkRowBtn.setOnClickListener { editUrl() }
        }
        binding.wgkRoutingDnsRow.apply {
            wgkRowIcon.setImageResource(R.drawable.ic_search)
            wgkRowLabel.setText(R.string.wgk_routing_dns_label)
            wgkRowBtn.setOnClickListener { editDns() }
        }
        binding.wgkRoutingProfileRow.info(R.drawable.ic_call_split, R.string.wgk_routing_profile_label)
        binding.wgkRoutingGeoipRow.info(R.drawable.ic_status_antenna, R.string.wgk_routing_geoip_label)
        binding.wgkRoutingGeositeRow.info(R.drawable.ic_key, R.string.wgk_routing_geosite_label)
        binding.wgkRoutingFetchedRow.info(R.drawable.ic_timer, R.string.wgk_routing_fetched_label)
        binding.wgkRoutingUpdateBtn.setOnClickListener { update() }
        // The button follows work that outlives this screen, so its state comes
        // from the flow rather than from a field: leaving and coming back must
        // not show an idle button over a download that is still running.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) { working.collect { renderBusy(it) } }
        }

        render()
    }

    override fun onDestroy() {
        dialog?.dismiss()
        dialog = null
        super.onDestroy()
    }

    private fun applyInsets() {
        ViewCompat.setOnApplyWindowInsetsListener(binding.wgkRoutingRoot) { _, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            binding.wgkRoutingToolbar.updatePadding(top = bars.top, left = bars.left, right = bars.right)
            binding.wgkRoutingScroll.updatePadding(left = bars.left, right = bars.right, bottom = bars.bottom)
            WindowInsetsCompat.CONSUMED
        }
    }

    /** A row that only reports: no chevron, no ripple. */
    private fun ViewWgkSettingsRowBinding.info(icon: Int, label: Int) {
        wgkRowIcon.setImageResource(icon)
        wgkRowLabel.setText(label)
        wgkRowChevron.isVisible = false
        wgkRowBtn.isClickable = false
        wgkRowBtn.isFocusable = false
        wgkRowValue.maxLines = 4
    }

    private fun render() {
        binding.wgkRoutingUrlRow.wgkRowValue.text = TetherSettings.routingProfileUrl(this)
        lifecycleScope.launch {
            val info = TetherRouting.info(this@RoutingSettingsActivity)
            val override = TetherSettings.routingDirectDns(this@RoutingSettingsActivity)
            binding.wgkRoutingDnsRow.wgkRowValue.text = override.ifEmpty {
                getString(R.string.wgk_routing_dns_from_profile, info?.domesticDns?.ifEmpty { "77.88.8.8" } ?: "77.88.8.8")
            }
            val none = getString(R.string.wgk_routing_none)
            binding.wgkRoutingProfileRow.wgkRowValue.text = info?.let {
                getString(R.string.wgk_routing_profile_value, it.name, formatRoutingDate(it.rulesUpdatedAt * 1000))
            } ?: none
            binding.wgkRoutingGeoipRow.wgkRowValue.text = info?.takeIf { it.geoipBytes > 0 }?.let {
                getString(R.string.wgk_routing_file_value, formatTetherBytes(it.geoipBytes), it.geoipUrl)
            } ?: none
            binding.wgkRoutingGeositeRow.wgkRowValue.text = info?.takeIf { it.geositeBytes > 0 }?.let {
                getString(R.string.wgk_routing_file_value, formatTetherBytes(it.geositeBytes), it.geositeUrl)
            } ?: none
            binding.wgkRoutingFetchedRow.wgkRowValue.text =
                info?.takeIf { it.fetchedAt > 0 }?.let { formatRoutingDate(it.fetchedAt) } ?: none
        }
    }

    private fun editUrl() {
        showTextDialog(
            title = R.string.wgk_routing_url_label,
            hint = R.string.wgk_routing_url_hint,
            current = TetherSettings.routingProfileUrl(this),
            validate = { v -> v.isEmpty() || v.startsWith("http://") || v.startsWith("https://") },
            invalid = R.string.wgk_routing_url_invalid,
        ) { value ->
            val before = TetherSettings.routingProfileUrl(this)
            TetherSettings.setRoutingProfileUrl(this, value)
            render()
            // A new profile is worth nothing until it is fetched, and the cache
            // was just discarded — so fetch it right away rather than at the
            // next sharing start.
            if (TetherSettings.routingProfileUrl(this) != before) update()
        }
    }

    private fun editDns() {
        showTextDialog(
            title = R.string.wgk_routing_dns_label,
            hint = R.string.wgk_routing_dns_hint,
            current = TetherSettings.routingDirectDns(this),
            validate = ::isDnsList,
            invalid = R.string.wgk_routing_dns_invalid,
        ) { value ->
            if (value == TetherSettings.routingDirectDns(this)) return@showTextDialog
            TetherSettings.setRoutingDirectDns(this, value)
            render()
            reloadOnly()
        }
    }

    /**
     * Comma-separated numeric addresses, each with an optional numeric port.
     *
     * Names are refused on purpose: the resolver is what resolves names, it
     * cannot itself be one. The check also has to be exactly as strict as Go's
     * parseDNSServers is forgiving — that one splits without validating, so
     * anything let through here that it cannot dial ("1.2.3.4:abc",
     * "8.8.8.8:53:1") means every direct-routed name fails to resolve, with
     * nothing anywhere saying why.
     */
    private fun isDnsList(value: String): Boolean {
        if (value.isEmpty()) return true
        return value.split(',').all { isDnsServer(it.trim()) }
    }

    private fun isDnsServer(raw: String): Boolean {
        if (raw.isEmpty()) return false
        // Brackets are the only way to hang a port on an IPv6 literal, and the
        // only form Go's SplitHostPort accepts for one.
        if (raw.startsWith("[")) {
            val close = raw.indexOf(']')
            if (close < 2) return false
            val rest = raw.substring(close + 1)
            return isIpv6(raw.substring(1, close)) &&
                (rest.isEmpty() || (rest.startsWith(":") && isPort(rest.substring(1))))
        }
        // More than one colon and no brackets: a bare IPv6 literal, no port.
        if (raw.count { it == ':' } > 1) return isIpv6(raw)
        val colon = raw.indexOf(':')
        if (colon < 0) return Patterns.IP_ADDRESS.matcher(raw).matches()
        return Patterns.IP_ADDRESS.matcher(raw.substring(0, colon)).matches() &&
            isPort(raw.substring(colon + 1))
    }

    private fun isPort(port: String): Boolean = (port.toIntOrNull() ?: 0) in 1..65535

    private fun isIpv6(host: String): Boolean =
        host.count { it == ':' } >= 2 && !host.contains(":::") &&
            host.all { it.isDigit() || it in "abcdefABCDEF:." }

    private fun showTextDialog(
        title: Int,
        hint: Int,
        current: String,
        validate: (String) -> Boolean,
        invalid: Int,
        onSave: (String) -> Unit,
    ) {
        val view = LayoutInflater.from(this).inflate(R.layout.wgk_text_input_dialog, null)
        val layout = view.findViewById<TextInputLayout>(R.id.wgk_input_layout)
        val field = view.findViewById<TextInputEditText>(R.id.wgk_input_text)
        layout.hint = getString(hint)
        field.setText(current)
        field.setSelection(current.length)
        val prompt = MaterialAlertDialogBuilder(this)
            .setTitle(title)
            .setView(view)
            .setPositiveButton(android.R.string.ok, null)
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        dialog?.dismiss()
        dialog = prompt
        prompt.setOnDismissListener { if (dialog === prompt) dialog = null }
        prompt.setOnShowListener {
            // Bound here rather than in the builder so a rejected value keeps the
            // dialog open with the error under the field.
            prompt.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener {
                val value = field.text?.toString()?.trim().orEmpty()
                if (!validate(value)) {
                    layout.error = getString(invalid)
                    return@setOnClickListener
                }
                prompt.dismiss()
                onSave(value)
            }
        }
        prompt.show()
    }

    /** Fetches the rules now and applies them to a live session. */
    private fun update() {
        val appContext = applicationContext
        runRoutingWork {
            val hadRules = TetherRouting.cachedDir(appContext) != null
            val dir = TetherRouting.prepare(appContext, force = true)
            when {
                dir == null ->
                    if (hadRules) R.string.wgk_routing_status_kept_old else R.string.wgk_routing_status_no_rules
                // With the switch off the running proxy is not using rules at
                // all, so restarting it would cut every client's connections to
                // no purpose whatsoever.
                !TetherSettings.isRoutingEnabled(appContext) -> R.string.wgk_routing_status_next_start
                else -> when (Application.getTetherManager().reloadRouting()) {
                    TetherManager.RoutingReload.APPLIED -> R.string.wgk_routing_status_applied
                    TetherManager.RoutingReload.NOT_SHARING -> R.string.wgk_routing_status_next_start
                    TetherManager.RoutingReload.FAILED -> R.string.wgk_routing_status_restart_failed
                }
            }
        }
    }

    /** Applies a changed setting to a live session without fetching anything. */
    private fun reloadOnly() {
        val appContext = applicationContext
        runRoutingWork {
            // Nothing to apply while the rules are switched off: the proxy holds
            // no profile, so the direct resolver this setting names does not
            // exist and a restart would only drop connections.
            if (!TetherSettings.isRoutingEnabled(appContext)) 0
            else when (Application.getTetherManager().reloadRouting()) {
                TetherManager.RoutingReload.APPLIED -> R.string.wgk_routing_status_dns_applied
                TetherManager.RoutingReload.NOT_SHARING -> 0
                TetherManager.RoutingReload.FAILED -> R.string.wgk_routing_status_restart_failed
            }
        }
    }

    /**
     * Runs [work] on the application scope — a download or a proxy restart must
     * not be abandoned because the user backed out of this screen — and, as
     * long as the screen is up, reports its status string when it is done.
     */
    private fun runRoutingWork(work: suspend () -> Int) {
        val job = applicationScope.async {
            working.value = pending.incrementAndGet() > 0
            try {
                // Queued, not dropped. Dropping is what made a profile address
                // edited during an update never get fetched: the follow-up was
                // refused because the first job was still running, and the user
                // was left on the old rules with the screen reporting success.
                workLock.withLock { work() }
            } catch (e: Exception) {
                Log.w(TAG, "routing work failed", e)
                R.string.wgk_routing_status_restart_failed
            } finally {
                working.value = pending.decrementAndGet() > 0
            }
        }
        lifecycleScope.launch {
            val status = job.await()
            showStatus(status)
            render()
        }
    }

    private fun showStatus(res: Int) {
        binding.wgkRoutingStatus.isVisible = res != 0
        if (res != 0) binding.wgkRoutingStatus.setText(res)
    }

    private fun renderBusy(value: Boolean) {
        binding.wgkRoutingUpdateBtn.isEnabled = !value
        binding.wgkRoutingUpdateBtn.setText(if (value) R.string.wgk_routing_updating else R.string.wgk_routing_update_btn)
    }

    companion object {
        /**
         * Routing work outlives this screen — a download and a proxy restart
         * must finish whether or not the user stays — so both the serialisation
         * and the "in progress" flag live at process scope. Kept in the activity
         * they died with it: coming back showed an enabled button over a job
         * still running, and a second press restarted the native proxy again,
         * cutting every tethered client's connections twice.
         */
        private val workLock = Mutex()
        private val pending = AtomicInteger()
        private val working = MutableStateFlow(false)
    }
}
