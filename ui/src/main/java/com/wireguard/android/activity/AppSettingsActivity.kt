/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.activity

import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.os.Bundle
import android.util.Log
import androidx.activity.enableEdgeToEdge
import androidx.annotation.ColorRes
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.isVisible
import androidx.core.view.updatePadding
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.wireguard.android.Application
import com.wireguard.android.R
import com.wireguard.android.databinding.AppSettingsActivityBinding
import com.wireguard.android.databinding.ViewWgkSettingsChoiceRowBinding
import com.wireguard.android.fragment.TetherSheet
import com.wireguard.android.fragment.TunnelState
import com.wireguard.android.tether.TetherRouting
import com.wireguard.android.tether.TetherSettings
import com.wireguard.android.tether.formatRoutingDate
import com.wireguard.android.tether.TetherState
import com.wireguard.android.tether.TetherToggle
import com.wireguard.android.tether.messageRes
import com.wireguard.android.turn.ConnectionMode
import com.wireguard.android.util.AuthStore
import com.wireguard.android.util.applicationScope
import com.wireguard.android.util.localeWrapped
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

/**
 * The app's own settings screen: everything that belongs to this fork and not to
 * upstream's androidx preferences screen.
 *
 * Each setting is grouped under a section header and answered in place — the
 * transport is picked from the two options themselves rather than from a dialog,
 * and sharing is switched on from its own row. Only what genuinely needs room of
 * its own still opens a sheet: the access point's credentials and QR code.
 */
class AppSettingsActivity : AppCompatActivity() {

    override fun attachBaseContext(newBase: Context) = super.attachBaseContext(newBase.localeWrapped())

    private lateinit var binding: AppSettingsActivityBinding
    private lateinit var tether: TetherToggle

    /**
     * Set when the user switches sharing on here, cleared once the sheet is up.
     *
     * Switching sharing on is itself the request for the QR: the passphrase is
     * generated per session, so the code has to be scanned right after the access
     * point comes up. It cannot be opened on the tap — there is nothing to encode
     * until the state turns Active — and the wait in between can span the
     * permission dialog, which takes this screen through onStop and back. Hence a
     * flag that outlives that round trip (and a rotation, through the saved
     * state) rather than a one-shot at the tap.
     */
    private var openSheetWhenActive = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Edge to edge on every API level, not just on 15+ where the platform
        // forces it: one inset path is far easier to reason about than two. This
        // also hands the bars their transparency and icon contrast, leaving only
        // the padding to applyInsets().
        enableEdgeToEdge()
        openSheetWhenActive = savedInstanceState?.getBoolean(STATE_OPEN_WHEN_ACTIVE) == true
        binding = AppSettingsActivityBinding.inflate(layoutInflater)
        setContentView(binding.root)
        applyInsets()
        binding.wgkSettingsToolbar.setNavigationOnClickListener { finish() }

        // Registers an activity result launcher, so it has to be built here and
        // not lazily on the first tap of the switch.
        tether = TetherToggle(this, this) { renderTether(Application.getTetherManager().state.value) }

        bindConnectionMode()
        bindTheme()
        if (bindTether()) {
            observeTether()
            // Arrived from the chip on the connect screen, which is the sharing
            // session itself asking to be opened — go straight to the sheet
            // rather than making the user find the row. Only on a fresh start:
            // a rotation would otherwise stack a second sheet on the restored one.
            if (savedInstanceState == null && intent.getBooleanExtra(EXTRA_OPEN_TETHER, false)) {
                openTetherSheet()
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(STATE_OPEN_WHEN_ACTIVE, openSheetWhenActive)
    }

    /**
     * The window is edge to edge, so the bars are this screen's to account for:
     * the toolbar grows into the status bar and paints it, the scroll view keeps
     * its last row clear of the navigation bar, and both take the sides for a
     * cutout or a gesture pill in landscape.
     */
    private fun applyInsets() {
        ViewCompat.setOnApplyWindowInsetsListener(binding.wgkSettingsRoot) { _, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            binding.wgkSettingsToolbar.updatePadding(top = bars.top, left = bars.left, right = bars.right)
            binding.wgkSettingsScroll.updatePadding(left = bars.left, right = bars.right, bottom = bars.bottom)
            WindowInsetsCompat.CONSUMED
        }
    }

    // ── Connection mode ────────────────────────────────────────────────────────

    private fun bindConnectionMode() {
        binding.wgkChoiceStandard.apply {
            wgkChoiceTitle.setText(R.string.wgk_connection_mode_standard_value)
            wgkChoiceDesc.setText(R.string.wgk_connection_mode_standard_desc)
            wgkChoiceRoot.setOnClickListener { setConnectionMode(reserve = false) }
        }
        binding.wgkChoiceReserve.apply {
            wgkChoiceTitle.setText(R.string.wgk_connection_mode_reserve_value)
            wgkChoiceDesc.setText(R.string.wgk_connection_mode_reserve_desc)
            wgkChoiceRoot.setOnClickListener { setConnectionMode(reserve = true) }
        }
        renderConnectionMode()
    }

    private fun setConnectionMode(reserve: Boolean) {
        if (ConnectionMode.isReserve(this) == reserve) return
        ConnectionMode.setReserve(this, reserve)
        renderConnectionMode()
    }

    private fun renderConnectionMode() {
        val reserve = ConnectionMode.isReserve(this)
        binding.wgkChoiceStandard.select(!reserve, R.color.wgk_primary)
        // The reserve transport is the non-default one, and it says so in warning
        // colour everywhere it shows: here, and on the gear in the main toolbar.
        binding.wgkChoiceReserve.select(reserve, R.color.wgk_warning)
    }

    private fun ViewWgkSettingsChoiceRowBinding.select(selected: Boolean, @ColorRes accent: Int) {
        wgkChoiceRoot.isSelected = selected
        wgkChoiceRadio.isChecked = selected
        wgkChoiceRadio.buttonTintList = ColorStateList(
            arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()),
            intArrayOf(
                ContextCompat.getColor(this@AppSettingsActivity, accent),
                ContextCompat.getColor(this@AppSettingsActivity, R.color.wgk_outline)
            )
        )
    }

    // ── Appearance ─────────────────────────────────────────────────────────────

    /**
     * The theme switch, moved here from an unlabelled icon in the connect screen's
     * toolbar.
     *
     * Two states and no "follow the system": the stored default is dark, and a
     * theme picked by hand is meant to stay picked. Flipping it recreates every
     * activity in the task — this one included — so the row is rendered from the
     * store on each bind and nothing has to be updated in place.
     */
    private fun bindTheme() {
        binding.wgkThemeRow.apply {
            wgkSwitchLabel.setText(R.string.wgk_theme_dark_label)
            // The switch already says which way this row is set; a value line
            // under the label would only repeat it.
            wgkSwitchValue.isVisible = false
            // Asks the store, not the switch it is about to flip. The switch is
            // only a projection of that store, and reading the next value off a
            // view means a tap does nothing at all if the view is ever out of
            // step: setDefaultNightMode ignores the mode it is already in.
            wgkSwitchRoot.setOnClickListener { setDarkTheme(!isDarkTheme()) }
        }
        renderTheme()
    }

    private fun setDarkTheme(dark: Boolean) {
        AuthStore.getInstance(this).setThemeMode(if (dark) "dark" else "light")
        AppCompatDelegate.setDefaultNightMode(
            if (dark) AppCompatDelegate.MODE_NIGHT_YES else AppCompatDelegate.MODE_NIGHT_NO
        )
    }

    /**
     * "light" or "dark" are the only values ever written, here and in the store's
     * own default, so anything else can only be dark.
     */
    private fun isDarkTheme(): Boolean = AuthStore.getInstance(this).getThemeMode() != "light"

    private fun renderTheme() {
        val dark = isDarkTheme()
        binding.wgkThemeRow.wgkSwitch.isChecked = dark
        binding.wgkThemeRow.wgkSwitchIcon.setImageResource(
            if (dark) R.drawable.ic_theme_dark else R.drawable.ic_theme_light
        )
    }

    // ── Internet sharing ───────────────────────────────────────────────────────

    /** Returns whether the section exists at all on this device. */
    private fun bindTether(): Boolean {
        // Sharing needs API 26 for startLocalOnlyHotspot; below that there is no
        // way to raise an access point at all, so the section is simply absent.
        val supported = Application.getTetherManager().isSupported
        binding.wgkTetherSection.isVisible = supported
        if (!supported) return false

        binding.wgkTetherSwitchRow.apply {
            wgkSwitchIcon.setImageResource(R.drawable.ic_wifi_tethering)
            wgkSwitchLabel.setText(R.string.wgk_tether_switch_label)
            wgkSwitchRoot.setOnClickListener {
                val enable = !wgkSwitch.isChecked
                openSheetWhenActive = enable
                tether.setEnabled(enable)
            }
        }
        bindTetherAutoOff()
        bindTetherRouting()
        binding.wgkTetherRoutingSettingsRow.apply {
            wgkRowIcon.setImageResource(R.drawable.ic_cloud)
            wgkRowLabel.setText(R.string.wgk_routing_settings_title)
            wgkRowBtn.setOnClickListener {
                startActivity(Intent(this@AppSettingsActivity, RoutingSettingsActivity::class.java))
            }
        }
        binding.wgkTetherDetailsRow.apply {
            wgkRowIcon.setImageResource(R.drawable.ic_action_scan_qr_code)
            wgkRowLabel.setText(R.string.wgk_tether_details_title)
            wgkRowBtn.setOnClickListener { openTetherSheet() }
        }
        renderTether(Application.getTetherManager().state.value)
        return true
    }

    /**
     * The idle auto-off switch.
     *
     * Bound once and never touched by renderTether: it is a stored preference, not
     * a property of whatever session happens to be running, so it stays readable
     * and switchable with sharing off — which is the only time most people will
     * be on this screen at all.
     */
    private fun bindTetherAutoOff() {
        binding.wgkTetherAutoOffRow.apply {
            wgkSwitchIcon.setImageResource(R.drawable.ic_timer)
            wgkSwitchLabel.setText(R.string.wgk_tether_auto_off_label)
            wgkSwitchValue.setText(R.string.wgk_tether_auto_off_desc)
            wgkSwitch.isChecked = TetherSettings.isAutoOffEnabled(this@AppSettingsActivity)
            wgkSwitchRoot.setOnClickListener {
                val enable = !wgkSwitch.isChecked
                TetherSettings.setAutoOffEnabled(this@AppSettingsActivity, enable)
                wgkSwitch.isChecked = enable
            }
        }
    }

    /**
     * The split-routing switch. A stored preference like auto-off, bound once.
     *
     * Switching it on is also the moment the rules are fetched: waiting for the
     * next sharing start meant the first start after the switch sat in
     * "Starting…" for the download's whole timeout and, past it, came up
     * without rules and said so — which read as broken. Fetched here, in the
     * background, the files are on disk long before anyone taps the sharing
     * switch. A live session picks the change up either way, through
     * [TetherManager.reloadRouting].
     */
    private fun bindTetherRouting() {
        binding.wgkTetherRoutingRow.apply {
            wgkSwitchIcon.setImageResource(R.drawable.ic_call_split)
            wgkSwitchLabel.setText(R.string.wgk_tether_routing_label)
            wgkSwitchValue.setText(R.string.wgk_tether_routing_desc)
            // The row's two-line cap is sized for a status word; this one carries
            // a sentence, which at a large font scale needs the third line.
            wgkSwitchValue.maxLines = 3
            wgkSwitch.isChecked = TetherSettings.isRoutingEnabled(this@AppSettingsActivity)
            wgkSwitchRoot.setOnClickListener {
                val enable = !wgkSwitch.isChecked
                TetherSettings.setRoutingEnabled(this@AppSettingsActivity, enable)
                wgkSwitch.isChecked = enable
                applyRoutingSwitch(enable)
            }
        }
    }

    /**
     * Fetches the rules (on) and applies the switch to a running session. The
     * work runs on the application scope so leaving the screen does not abandon
     * a half-finished download; this screen only waits on it to refresh the
     * summary row.
     */
    private fun applyRoutingSwitch(enable: Boolean) {
        val appContext = applicationContext
        if (enable) {
            binding.wgkTetherRoutingSettingsRow.wgkRowValue.setText(R.string.wgk_routing_fetching)
        }
        val work = applicationScope.launch {
            try {
                if (enable) TetherRouting.prepare(appContext)
                Application.getTetherManager().reloadRouting()
            } catch (e: Exception) {
                Log.w(TAG, "applying the routing switch failed", e)
            }
        }
        lifecycleScope.launch {
            work.join()
            renderRoutingSummary()
        }
    }

    override fun onResume() {
        super.onResume()
        // The routing screen may have fetched or discarded rules while this one
        // was behind it, so the summary is re-read on every return, not bound once.
        if (Application.getTetherManager().isSupported) renderRoutingSummary()
    }

    private fun renderRoutingSummary() {
        lifecycleScope.launch {
            val info = TetherRouting.info(this@AppSettingsActivity)
            binding.wgkTetherRoutingSettingsRow.wgkRowValue.text = if (info == null) {
                getString(R.string.wgk_routing_none)
            } else {
                getString(R.string.wgk_routing_profile_value, info.name, formatRoutingDate(info.rulesUpdatedAt * 1000))
            }
        }
    }

    private fun observeTether() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                Application.getTetherManager().state.collect {
                    renderTether(it)
                    // Only from here, and not from renderTether(): the sheet is a
                    // fragment transaction, and this is the one caller the
                    // lifecycle guarantees is STARTED — renderTether also runs off
                    // the permission callback, which can land after onStop.
                    if (openSheetWhenActive && it is TetherState.Active) {
                        openSheetWhenActive = false
                        openTetherSheet()
                    }
                }
            }
        }
        // Sharing can only be raised over a live tunnel, and the tunnel can come
        // up or fall over while this screen sits open. Only the up/down edge
        // matters here — the tracker also emits on every traffic counter tick.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                Application.getTunnelStateTracker().uiState
                    .map { it.state == TunnelState.Connected }
                    .distinctUntilChanged()
                    .collect { renderTether(Application.getTetherManager().state.value) }
            }
        }
    }

    /** No-ops when the sheet is already up: the row and the switch can race. */
    private fun openTetherSheet() {
        if (supportFragmentManager.findFragmentByTag(TAG_TETHER) != null) return
        TetherSheet().show(supportFragmentManager, TAG_TETHER)
    }

    private fun renderTether(state: TetherState) {
        if (!Application.getTetherManager().isSupported) return
        val tunnelUp = Application.getTunnelStateTracker().uiState.value.state == TunnelState.Connected
        val active = state is TetherState.Active

        val row = binding.wgkTetherSwitchRow
        row.wgkSwitch.isChecked = active || state is TetherState.Starting
        // An access point that is already up stays switchable whatever the tunnel
        // is doing — otherwise there would be no way to turn it off.
        val switchable = tunnelUp || active
        row.wgkSwitchRoot.isEnabled = switchable
        row.wgkSwitch.isEnabled = switchable
        row.wgkSwitchRoot.alpha = if (switchable) 1f else DISABLED_ALPHA
        row.wgkSwitchValue.text = when (state) {
            is TetherState.Active ->
                resources.getQuantityString(R.plurals.wgk_tether_clients, state.clients, state.clients)
            TetherState.Starting -> getString(R.string.wgk_tether_starting_value)
            else -> getString(R.string.wgk_tether_off_value)
        }

        // The credentials only exist while an access point is up.
        binding.wgkTetherDetailsDivider.isVisible = active
        binding.wgkTetherDetailsRow.root.isVisible = active
        binding.wgkTetherDetailsRow.wgkRowValue.text = (state as? TetherState.Active)?.ssid.orEmpty()

        val status = when {
            state is TetherState.Failed -> getString(state.reason.messageRes())
            !tunnelUp && !active -> getString(R.string.wgk_tether_needs_tunnel)
            else -> ""
        }
        binding.wgkTetherStatus.text = status
        binding.wgkTetherStatus.isVisible = status.isNotEmpty()
        binding.wgkTetherStatus.setTextColor(
            ContextCompat.getColor(
                this,
                if (state is TetherState.Failed && state.reason.isFailure) R.color.wgk_warning
                else R.color.wgk_on_surface_variant
            )
        )
    }

    companion object {
        /** Boolean extra: open the sharing sheet as soon as the screen is up. */
        const val EXTRA_OPEN_TETHER = "open_tether"

        private const val TAG = "WireGuard/AppSettings"
        private const val STATE_OPEN_WHEN_ACTIVE = "open_tether_when_active"
        private const val TAG_TETHER = "tether_sheet"
        private const val DISABLED_ALPHA = 0.6f
    }
}
