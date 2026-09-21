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
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.wireguard.android.Application
import com.wireguard.android.BuildConfig
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
import com.wireguard.android.turn.RelayTransport
import com.wireguard.android.updater.GithubReleases
import com.wireguard.android.updater.UpdateActivity
import com.wireguard.android.util.AuthStore
import com.wireguard.android.util.ThemeMode
import com.wireguard.android.util.applicationScope
import com.wireguard.android.util.localeWrapped
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

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
        bindRelayTransport()
        bindAutoRefresh()
        bindTheme()
        bindUpdateCheck()
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

    // ── Relay transport ────────────────────────────────────────────────────────

    /**
     * Three choices, not a switch: the operator is recognised on its own, so there
     * has to be a way to overrule it in either direction — TCP for a SIM the rule
     * does not know or a router carrying one, UDP for an RTK SIM where the network
     * is not whitelisted. See [RelayTransport].
     */
    private fun bindRelayTransport() {
        binding.wgkTransportAuto.apply {
            wgkChoiceTitle.setText(R.string.wgk_relay_transport_auto_value)
            wgkChoiceDesc.setText(R.string.wgk_relay_transport_auto_desc)
            wgkChoiceRoot.setOnClickListener { setRelayTransport(RelayTransport.Mode.AUTO) }
        }
        binding.wgkTransportUdp.apply {
            wgkChoiceTitle.setText(R.string.wgk_relay_transport_udp_value)
            wgkChoiceDesc.setText(R.string.wgk_relay_transport_udp_desc)
            wgkChoiceRoot.setOnClickListener { setRelayTransport(RelayTransport.Mode.UDP) }
        }
        binding.wgkTransportTcp.apply {
            wgkChoiceTitle.setText(R.string.wgk_relay_transport_tcp_value)
            wgkChoiceDesc.setText(R.string.wgk_relay_transport_tcp_desc)
            wgkChoiceRoot.setOnClickListener { setRelayTransport(RelayTransport.Mode.TCP) }
        }
        binding.wgkTransportAuto.compact()
        binding.wgkTransportUdp.compact()
        binding.wgkTransportTcp.compact()
        renderRelayTransport()
    }

    private fun setRelayTransport(mode: RelayTransport.Mode) {
        if (RelayTransport.mode(this) == mode) return
        RelayTransport.setMode(this, mode)
        renderRelayTransport()
        // Takes effect on the next dial, without a reconnect: see onRelayTransportChanged.
        Application.getTurnProxyManager().onRelayTransportChanged()
    }

    private fun renderRelayTransport() {
        val mode = RelayTransport.mode(this)
        binding.wgkTransportAuto.select(mode == RelayTransport.Mode.AUTO, R.color.wgk_primary)
        binding.wgkTransportUdp.select(mode == RelayTransport.Mode.UDP, R.color.wgk_primary)
        // The slower transport, in the same warning colour as the fallback mode.
        binding.wgkTransportTcp.select(mode == RelayTransport.Mode.TCP, R.color.wgk_warning)
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

    /**
     * The slimmer row of the cards that are set once and left alone — relay
     * transport and theme — under the full-height rows of sharing and the
     * connection mode, which are what this screen is opened for.
     *
     * Only the height goes: the radio keeps its 48dp width, so its circle stays
     * on the same vertical line as the radios and switches of the other cards.
     * Both minimums are cleared because a radio is a TextView, which keeps a
     * minimum height of its own next to the View one, and the style sets both.
     */
    private fun ViewWgkSettingsChoiceRowBinding.compact() {
        val pad = resources.getDimensionPixelSize(R.dimen.wgk_settings_choice_compact_pad)
        wgkChoiceRoot.minimumHeight = resources.getDimensionPixelSize(R.dimen.wgk_settings_choice_compact_min)
        wgkChoiceRoot.updatePadding(top = pad, bottom = pad)
        wgkChoiceRadio.minHeight = 0
        wgkChoiceRadio.minimumHeight = 0
    }

    private fun bindAutoRefresh() {
        val auth = AuthStore.getInstance(this)
        binding.wgkAutoRefreshRow.apply {
            wgkSwitchIcon.setImageResource(R.drawable.ic_auto_renew)
            wgkSwitchLabel.setText(R.string.wgk_auto_refresh_label)
            wgkSwitchValue.setText(R.string.wgk_auto_refresh_desc)
            wgkSwitch.isChecked = auth.isAutoRefreshEnabled()
            wgkSwitchRoot.setOnClickListener {
                val enabled = !auth.isAutoRefreshEnabled()
                auth.setAutoRefreshEnabled(enabled)
                wgkSwitch.isChecked = enabled
            }
        }
    }

    // ── Appearance ─────────────────────────────────────────────────────────────

    /**
     * The theme, moved here from an unlabelled icon in the connect screen's
     * toolbar: the phone's own, or light or dark picked by hand. The stored
     * default stays dark (see [ThemeMode]); following the system is opt-in.
     */
    private fun bindTheme() {
        binding.wgkThemeSystem.apply {
            wgkChoiceTitle.setText(R.string.wgk_theme_system_value)
            wgkChoiceDesc.setText(R.string.wgk_theme_system_desc)
            wgkChoiceRoot.setOnClickListener { setTheme(ThemeMode.SYSTEM) }
        }
        // Light and dark need no second line: the name is the whole of it.
        binding.wgkThemeLight.apply {
            wgkChoiceTitle.setText(R.string.wgk_theme_light_value)
            wgkChoiceDesc.isVisible = false
            wgkChoiceRoot.setOnClickListener { setTheme(ThemeMode.LIGHT) }
        }
        binding.wgkThemeDark.apply {
            wgkChoiceTitle.setText(R.string.wgk_theme_dark_value)
            wgkChoiceDesc.isVisible = false
            wgkChoiceRoot.setOnClickListener { setTheme(ThemeMode.DARK) }
        }
        binding.wgkThemeSystem.compact()
        binding.wgkThemeLight.compact()
        binding.wgkThemeDark.compact()
        renderTheme()
    }

    private fun setTheme(mode: ThemeMode) {
        val store = AuthStore.getInstance(this)
        if (store.getThemeMode() == mode) return
        store.setThemeMode(mode)
        // Rendered here and not left to the recreation: that only happens when
        // the colours actually change, and going from dark to "as on the phone"
        // on a phone that is itself dark changes none — the radio would stay
        // where it was.
        renderTheme()
        AppCompatDelegate.setDefaultNightMode(mode.nightMode)
    }

    private fun renderTheme() {
        val mode = AuthStore.getInstance(this).getThemeMode()
        binding.wgkThemeSystem.select(mode == ThemeMode.SYSTEM, R.color.wgk_primary)
        binding.wgkThemeLight.select(mode == ThemeMode.LIGHT, R.color.wgk_primary)
        binding.wgkThemeDark.select(mode == ThemeMode.DARK, R.color.wgk_primary)
    }

    // ── Update check ───────────────────────────────────────────────────────────

    /** What the row says; [Available] also changes what a tap does. */
    private sealed interface UpdateCheck {
        data object Idle : UpdateCheck
        data object Running : UpdateCheck
        data object Latest : UpdateCheck
        data class Available(val release: GithubReleases.Release) : UpdateCheck
        data class Failed(val message: String) : UpdateCheck
    }

    private var updateCheck: UpdateCheck = UpdateCheck.Idle

    /**
     * The installed version, and a check for a newer one on GitHub made by hand.
     *
     * The server already announces updates with the config, but only when a config
     * is fetched and only what it has been told about; this asks the place the
     * releases are published, whenever the user wants to know. Installing is the
     * same [UpdateActivity] either way, with the same package, version and
     * signature checks — GitHub is where the file is fetched from, not why it is
     * trusted.
     *
     * Absent without a repository to ask, and in the Play build, which the store
     * updates and which may not update itself.
     */
    private fun bindUpdateCheck() {
        val repo = BuildConfig.RELEASES_REPO
        val offered = BuildConfig.BUILD_TYPE != "googleplay" && GithubReleases.isRepo(repo)
        binding.wgkUpdateSection.isVisible = offered
        if (!offered) return
        binding.wgkUpdateRow.apply {
            wgkRowIcon.setImageResource(R.drawable.ic_refresh)
            wgkRowLabel.text = getString(R.string.wgk_update_check_label, BuildConfig.VERSION_NAME)
            wgkRowChevron.isVisible = false
            wgkRowBtn.setOnClickListener {
                when (val state = updateCheck) {
                    UpdateCheck.Running -> Unit
                    is UpdateCheck.Available -> offerUpdate(state.release)
                    else -> checkForUpdate(repo)
                }
            }
        }
        renderUpdateCheck()
    }

    private fun checkForUpdate(repo: String) {
        updateCheck = UpdateCheck.Running
        renderUpdateCheck()
        lifecycleScope.launch {
            updateCheck = try {
                val release = withContext(Dispatchers.IO) { GithubReleases.latest(repo) }
                if (GithubReleases.isNewer(release.version, BuildConfig.VERSION_NAME)) UpdateCheck.Available(release)
                else UpdateCheck.Latest
            } catch (e: CancellationException) {
                throw e
            } catch (_: GithubReleases.NoReleaseException) {
                UpdateCheck.Failed(getString(R.string.wgk_update_check_no_release))
            } catch (e: Exception) {
                Log.w(TAG, "Update check failed", e)
                UpdateCheck.Failed(getString(R.string.wgk_update_check_failed, e.localizedMessage ?: e.javaClass.simpleName))
            }
            renderUpdateCheck()
            (updateCheck as? UpdateCheck.Available)?.let { offerUpdate(it.release) }
        }
    }

    /** The same question the config refresh asks when the server names a newer version. */
    private fun offerUpdate(release: GithubReleases.Release) {
        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.wgk_update_available_title, release.version))
            .setMessage(R.string.wgk_update_available_message)
            .setPositiveButton(R.string.wgk_update_now) { _, _ -> UpdateActivity.open(this, release.downloadUrl) }
            .setNegativeButton(R.string.wgk_update_later, null)
            .show()
    }

    private fun renderUpdateCheck() {
        binding.wgkUpdateRow.wgkRowValue.apply {
            val state = updateCheck
            text = when (state) {
                UpdateCheck.Idle -> getString(R.string.wgk_update_check_idle)
                UpdateCheck.Running -> getString(R.string.wgk_update_check_running)
                UpdateCheck.Latest -> getString(R.string.wgk_update_check_latest)
                is UpdateCheck.Available -> getString(R.string.wgk_update_check_available, state.release.version)
                is UpdateCheck.Failed -> state.message
            }
            setTextColor(ContextCompat.getColor(this@AppSettingsActivity, when (state) {
                is UpdateCheck.Available -> R.color.wgk_primary
                is UpdateCheck.Failed -> R.color.wgk_warning
                else -> R.color.wgk_on_surface_variant
            }))
        }
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
            wgkSwitchValue.setTextAppearance(R.style.TextAppearance_WGKeyBot_InstrumentValue)
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
        val switchable = tunnelUp || active || state is TetherState.Starting
        row.wgkSwitchRoot.isEnabled = switchable
        row.wgkSwitch.isEnabled = switchable
        row.wgkSwitchRoot.alpha = if (switchable) 1f else DISABLED_ALPHA
        row.wgkSwitchValue.text = when (state) {
            is TetherState.Active -> getString(R.string.wgk_sharing_connections, state.connections)
            TetherState.Starting -> getString(R.string.wgk_sharing_starting)
            else -> getString(R.string.wgk_sharing_off)
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
