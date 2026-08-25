/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.fragment

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.res.ColorStateList
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.AccelerateDecelerateInterpolator
import android.view.animation.LinearInterpolator
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.core.graphics.ColorUtils
import androidx.core.view.isVisible
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.wireguard.android.Application
import com.wireguard.android.BuildConfig
import com.wireguard.android.R
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.databinding.TunnelListFragmentBinding
import com.wireguard.android.databinding.ViewWgkConnectButtonBinding
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.tether.TetherState
import com.wireguard.android.turn.ConnectionMode
import com.wireguard.android.util.ApiClient
import com.wireguard.android.util.AuthStore
import com.wireguard.android.util.ErrorMessages
import com.wireguard.android.viewmodel.ConfigProxy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.activity.result.contract.ActivityResultContracts
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.wireguard.android.activity.AppSettingsActivity
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.turn.TurnConfigProcessor
import com.wireguard.android.util.TokenFormat
import com.wireguard.android.widget.TvTokenKeyboard
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private const val TUNNEL_NAME = "wgkeybot"
private const val PREFS_CONFIG_LOAD = "config_load_prefs"          // legacy (migration only)
private const val PREFS_CONFIG_LOAD_SECURE = "config_load_secure"  // encrypted
private const val KEY_CONFIG_LOADED_AT = "config_loaded_at"

class TunnelListFragment : BaseFragment() {

    private var binding: TunnelListFragmentBinding? = null
    private val vm: TunnelListViewModel by viewModels()
    private var pendingTunnel: ObservableTunnel? = null
    private var tvKeyboard: TvTokenKeyboard? = null
    private var refreshAnim: ObjectAnimator? = null
    private var buttonAnim: ValueAnimator? = null
    private var _prefs: SharedPreferences? = null

    private var currentSplitProxy: ConfigProxy? = null
    private var updateShownThisSession = false
    private var wizardLaunchedThisSession = false

    /**
     * The last state rendered into the current view tree, for the render diff.
     * [render] runs on every poll tick — every two seconds while the screen is on
     * — and all but the traffic figures change only when the state does, so the
     * chrome (icons, colours, stage bars, the animated ring alphas) is rendered
     * off this comparison rather than unconditionally. Null whenever the views
     * have just been created and nothing is on them yet.
     */
    private var rendered: TunnelUiState? = null

    /** Clients on the access point, or -1 when sharing is not up. */
    private var tetherClients = -1

    /** What the action slot is currently showing, same idea as [rendered]. */
    private var renderedSlotKey: Pair<TunnelState, Int>? = null

    private var logTapCount = 0
    private var logTapLastMs = 0L
    private val LOG_TAPS_REQUIRED = 8
    private val LOG_TAP_RESET_MS = 3_000L

    // ── VPN permission launcher ────────────────────────────────────────────────

    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val tunnel = pendingTunnel ?: return@registerForActivityResult
            pendingTunnel = null
            if (result.resultCode == android.app.Activity.RESULT_OK) {
                lifecycleScope.launch {
                    try {
                        // Use the real resulting state: an atomic connect may end DOWN
                        // (handshake failed and was torn down, or cancelled concurrently).
                        val resultState = tunnel.setStateAsync(Tunnel.State.UP)
                        if (resultState == Tunnel.State.UP) vm.notifyTunnelUp() else vm.notifyTunnelDown()
                    } catch (e: Exception) {
                        vm.notifyTunnelDown()
                        showSnackbar(ErrorMessages[e])
                    }
                }
            } else {
                vm.notifyTunnelDown()
            }
        }

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        super.onCreateView(inflater, container, savedInstanceState)

        binding = TunnelListFragmentBinding.inflate(inflater, container, false)
        binding?.apply {
            wgkConnectButtonView.wgkConnectBtn.setOnClickListener { toggleWgKeybot() }
            wgkFooterRow.wgkSplitBtn.setOnClickListener { openSplitTunnelDialog() }
            // TV only: the phone screen moved this row to the settings screen, so
            // on a phone this view is absent and the binding field is null.
            wgkFooterRow.wgkConnectionModeBtn?.setOnClickListener {
                ConnectionMode.showDialog(requireContext()) { updateConnectionModeButton() }
            }
            updateConnectionModeButton()
            // Phone only: the TV layout has no action slot and no sharing.
            wgkTetherChip?.setOnClickListener {
                startActivity(
                    Intent(requireContext(), AppSettingsActivity::class.java)
                        .putExtra(AppSettingsActivity.EXTRA_OPEN_TETHER, true)
                )
            }
            wgkProfileCard.wgkRefreshBtn.setOnClickListener { refreshConfig() }
            wgkProfileCard.wgkAutoRefreshBtn.setOnClickListener { toggleAutoRefresh() }
            wgkProfileCard.wgkProfileIcon.setOnClickListener { onLogIconTap() }
        }

        // Register once so stale pending results from previous dialogs don't re-fire.
        childFragmentManager.setFragmentResultListener(
            AppListDialogFragment.REQUEST_SELECTION, viewLifecycleOwner
        ) { _, bundle ->
            val proxy = currentSplitProxy ?: return@setFragmentResultListener
            currentSplitProxy = null
            val newSelections = bundle.getStringArray(AppListDialogFragment.KEY_SELECTED_APPS)
                ?: return@setFragmentResultListener
            val excluded = bundle.getBoolean(AppListDialogFragment.KEY_IS_EXCLUDED)
            saveSplitTunnelApps(proxy, newSelections.toList(), excluded)
        }

        // First-launch split-tunneling wizard result.
        childFragmentManager.setFragmentResultListener(
            SplitTunnelWizardFragment.REQUEST_WIZARD, viewLifecycleOwner
        ) { _, bundle ->
            when (bundle.getString(SplitTunnelWizardFragment.KEY_MODE)) {
                SplitTunnelWizardFragment.MODE_INCLUDE -> openSplitTunnelDialog(forceExcluded = false)
                SplitTunnelWizardFragment.MODE_EXCLUDE -> openSplitTunnelDialog(forceExcluded = true)
                SplitTunnelWizardFragment.MODE_LATER ->
                    showSnackbar(getString(R.string.wgk_split_wizard_later_hint))
            }
        }

        syncConfigLoadedAt()

        // Only the client count moves the chip, and the sharing state flow also
        // ticks for the byte counters — collapse it to the one number rendered.
        if (Application.getTetherManager().isSupported) {
            lifecycleScope.launch {
                repeatOnLifecycle(Lifecycle.State.STARTED) {
                    Application.getTetherManager().state
                        .map { (it as? TetherState.Active)?.clients ?: -1 }
                        .distinctUntilChanged()
                        .collect { clients ->
                            tetherClients = clients
                            val b = binding ?: return@collect
                            renderActionSlot(b, vm.uiState.value.state)
                        }
                }
            }
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                vm.uiState.collect {
                    render(it)
                    // Deferred auto-refresh: the tunnel is now up, so the config
                    // server is reachable even if it's DPI-blocked off-VPN.
                    if (vm.pendingAutoRefresh && it.state == TunnelState.Connected) {
                        vm.pendingAutoRefresh = false
                        refreshConfig(manual = false)
                    }
                }
            }
        }

        return binding?.root
    }

    override fun onResume() {
        super.onResume()
        refreshButtonState()
        updateConnectionModeButton()
    }

    override fun onDestroyView() {
        refreshAnim?.cancel()
        refreshAnim = null
        // Cleared first, same as in renderConnectButton: the cancel runs the end
        // callback, which must see that it no longer owns the control.
        buttonAnim.also { buttonAnim = null }?.cancel()
        // The diff describes views that are about to go away; a stale entry would
        // leave the next view tree unrendered until the state happened to change.
        rendered = null
        renderedSlotKey = null
        binding = null
        _prefs = null
        super.onDestroyView()
    }

    override fun onSelectedTunnelChanged(oldTunnel: ObservableTunnel?, newTunnel: ObservableTunnel?) = Unit

    // ── Toggle tunnel ──────────────────────────────────────────────────────────

    private fun toggleWgKeybot() {
        lifecycleScope.launch {
            try {
                val tunnel = Application.getTunnelManager().getTunnels()
                    .firstOrNull { it.name == TUNNEL_NAME }
                if (tunnel == null) {
                    showSnackbar(getString(R.string.wgk_config_not_found))
                    return@launch
                }

                // A single tap should reliably disconnect when the UI shows any non-idle
                // state — Connecting/Handshake/Reconnecting all mean "user wants to
                // stop", even if isConnecting was already cleared by notifyTunnelUp.
                //
                // Failed is deliberately not in that set. It covers two situations: the
                // handshake watchdog gave up on a tunnel that is still UP — caught by
                // the tunnel.state check below — and a terminal TURN failure that
                // already took the tunnel down and left its reason on screen. In the
                // second one the button says "tap to retry", and treating the tap as a
                // stop would spend it on a tunnel that is already down.
                val uiBusy = vm.uiState.value.state != TunnelState.Disconnected &&
                        vm.uiState.value.state != TunnelState.Failed
                val newState = if (tunnel.state == Tunnel.State.UP || vm.isConnecting || uiBusy)
                    Tunnel.State.DOWN else Tunnel.State.UP

                if (newState == Tunnel.State.UP && Application.getBackend() is GoBackend) {
                    val intent = GoBackend.VpnService.prepare(requireContext())
                    if (intent != null) {
                        pendingTunnel = tunnel
                        vm.cancelledByUser = false
                        vm.notifyConnecting()
                        vpnPermissionLauncher.launch(intent)
                        return@launch
                    }
                }

                if (newState == Tunnel.State.UP) {
                    vm.cancelledByUser = false
                    vm.notifyConnecting()
                } else {
                    // Reset UI to Disconnected before the (possibly slow) backend teardown
                    // so the user sees the tap landed immediately and doesn't tap again.
                    vm.cancelledByUser = true
                    vm.notifyTunnelDown()
                    // Stop TURN through the manager, not just the native proxy. When
                    // cancelling a still-connecting tunnel, setStateAsync(DOWN) below
                    // early-returns (tunnel.state is already DOWN) and never reaches
                    // stopForTunnel — so userInitiatedStop would stay false and
                    // performRestartSequence would keep reconnecting after the stop.
                    withContext(Dispatchers.IO) {
                        Application.getTurnProxyManager().stopForTunnel(TUNNEL_NAME)
                    }
                }

                // Judge by the real resulting state, not the requested one: an atomic
                // connect can end DOWN if the WireGuard handshake never completes.
                val resultState = tunnel.setStateAsync(newState)
                if (resultState == Tunnel.State.UP) vm.notifyTunnelUp() else vm.notifyTunnelDown()
            } catch (e: Exception) {
                vm.notifyTunnelDown()
                if (!vm.cancelledByUser) showSnackbar(ErrorMessages[e])
            } finally {
                if (pendingTunnel == null) {
                    vm.cancelledByUser = false
                }
            }
        }
    }

    // ── refreshButtonState ─────────────────────────────────────────────────────

    fun refreshState() = refreshButtonState()

    private fun refreshButtonState() {
        lifecycleScope.launch {
            val b = binding ?: return@launch
            val auth = AuthStore.getInstance(requireContext())

            // Auth gate — must check before tunnel lookup
            when {
                !auth.hasAuth() -> {
                    showNoAuthContainer(b, expired = false)
                    return@launch
                }
                auth.isSubscriptionExpired() -> {
                    showNoAuthContainer(b, expired = true)
                    return@launch
                }
            }

            val tunnel = Application.getTunnelManager().getTunnels()
                .firstOrNull { it.name == TUNNEL_NAME }

            if (tunnel == null) {
                // Has valid auth but config missing locally — auto-fetch
                refreshConfig()
                return@launch
            }

            tvKeyboard?.detach()
            b.wgkNoConfigContainer.isVisible = false
            b.wgkProfileCard.root.isVisible = true
            b.wgkConnectButtonView.root.isVisible = true
            // On a phone the hint lives inside the action slot and its visibility is
            // the slot's business; on TV there is no slot and the hint is the band.
            (b.wgkActionSlot ?: b.wgkHeadline).isVisible = true
            renderedSlotKey = null
            renderActionSlot(b, vm.uiState.value.state)
            b.wgkStatusZone.root.isVisible = true
            b.wgkFooterRow.root.isVisible = true

            if (isTv()) {
                // Give the D-pad an explicit landing spot when the control UI
                // first appears; don't steal focus if the user already moved it.
                val connectBtn = b.wgkConnectButtonView.wgkConnectBtn
                connectBtn.post {
                    val bb = binding ?: return@post
                    if (bb.mainContainer.findFocus() == null) connectBtn.requestFocus()
                }
            }

            renderAutoRefreshIcon(b)
            checkAutoRefresh(auth)

            if (tunnel.state == Tunnel.State.UP && !vm.isConnecting) {
                vm.ensurePollingActive()
            } else if (tunnel.state != Tunnel.State.UP && !vm.isConnecting &&
                vm.uiState.value.state != TunnelState.Disconnected &&
                vm.uiState.value.failure == null) {
                // Tunnel was stopped externally (widget, QS tile) while we were
                // not visible — reset the UI so we don't show a stale Failed /
                // Connecting state.
                //
                // A reported failure is exempt: it is a down tunnel by design, and
                // this runs on every onResume — the reason would be wiped before
                // the user who came to find out what happened could read it.
                vm.notifyTunnelDown()
            }

            // Split tunneling row value. The label is fixed; only the value moves,
            // so the row keeps a stable left edge whatever the app count is.
            val config = tunnel.getConfigAsync()
            val appsActive = config.`interface`.includedApplications.isNotEmpty() ||
                    config.`interface`.excludedApplications.isNotEmpty()
            b.wgkFooterRow.wgkSplitValue.text = when {
                config.`interface`.includedApplications.isNotEmpty() ->
                    getString(R.string.wgk_split_only_count, config.`interface`.includedApplications.size)
                config.`interface`.excludedApplications.isNotEmpty() ->
                    getString(R.string.wgk_split_excluded_count, config.`interface`.excludedApplications.size)
                else -> getString(R.string.wgk_split_off_value)
            }
            val splitColor = ContextCompat.getColor(
                requireContext(),
                if (appsActive) R.color.wgk_on_surface else R.color.wgk_on_surface_variant
            )
            b.wgkFooterRow.wgkSplitValue.setTextColor(splitColor)
            b.wgkFooterRow.wgkSplitIcon.imageTintList = ColorStateList.valueOf(splitColor)

            maybeShowSplitWizard(auth, appsActive)
        }
    }

    /**
     * Show the one-time split-tunneling wizard on first launch with an active subscription and a
     * loaded config. Marks itself shown the moment it appears so it survives a process restart and
     * never nags users who already have split tunneling configured.
     */
    private fun maybeShowSplitWizard(auth: AuthStore, appsActive: Boolean) {
        if (wizardLaunchedThisSession || auth.isSplitWizardShown()) return
        // Can't commit a fragment transaction once state is saved — retry on the next refresh.
        if (childFragmentManager.isStateSaved) return
        if (appsActive) { auth.setSplitWizardShown(); return }
        if (childFragmentManager.findFragmentByTag(TAG_SPLIT_WIZARD) != null) return
        wizardLaunchedThisSession = true
        auth.setSplitWizardShown()
        SplitTunnelWizardFragment().show(childFragmentManager, TAG_SPLIT_WIZARD)
    }

    private fun isTv(): Boolean {
        val uiType = resources.configuration.uiMode and Configuration.UI_MODE_TYPE_MASK
        return uiType == Configuration.UI_MODE_TYPE_TELEVISION ||
               requireContext().packageManager.hasSystemFeature(PackageManager.FEATURE_LEANBACK)
    }

    private fun showNoAuthContainer(b: TunnelListFragmentBinding, expired: Boolean) {
        vm.notifyTunnelDown()
        b.wgkNoConfigContainer.isVisible = true
        b.wgkProfileCard.root.isVisible = false
        b.wgkConnectButtonView.root.isVisible = false
        (b.wgkActionSlot ?: b.wgkHeadline).isVisible = false
        b.wgkStatusZone.root.isVisible = false
        b.wgkFooterRow.root.isVisible = false

        b.wgkNoKeyTitle.text = getString(
            if (expired) R.string.wgk_expired_title else R.string.wgk_no_key_title
        )
        b.wgkNoKeySubtitle.text = getString(
            if (expired) R.string.wgk_expired_subtitle else R.string.wgk_no_key_subtitle
        )
        b.wgkBotLinkBtn.setOnClickListener {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/wg_key_bot")))
        }

        if (isTv()) {
            // TV: hide mobile input, show D-pad keyboard
            b.wgkTokenInputWrapper.isVisible = false
            b.wgkConnectWithTokenBtn.isVisible = false
            if (tvKeyboard == null) {
                tvKeyboard = TvTokenKeyboard(requireContext()) { token ->
                    initWithToken(token)
                }
            }
            tvKeyboard?.setVisible(true)
            // Mount into the dedicated TV keyboard column; fall back to the
            // container itself on layouts without it (defensive — TV layout has it).
            val keyboardHost = (b.wgkTvKeyboardHost ?: b.wgkNoConfigContainer) as? ViewGroup
            if (keyboardHost != null) tvKeyboard?.attachTo(keyboardHost)
        } else {
            b.wgkTokenInputWrapper.isVisible = true
            b.wgkConnectWithTokenBtn.isVisible = true
            tvKeyboard?.detach()
            b.wgkPasteBtn.setOnClickListener {
                pasteTokenFromClipboard(b)
            }
            b.wgkConnectWithTokenBtn.setOnClickListener {
                val token = TokenFormat.normalize(b.wgkTokenInput.text?.toString() ?: "")
                if (token.isEmpty()) {
                    showSnackbar(getString(R.string.wgk_token_error_empty))
                    return@setOnClickListener
                }
                if (!TokenFormat.isValid(token)) {
                    showSnackbar(getString(R.string.wgk_token_error_format))
                    return@setOnClickListener
                }
                initWithToken(token)
            }
        }

        if (expired) {
            b.wgkCheckSubscriptionBtn.isVisible = true
            b.wgkCheckSubscriptionBtn.setOnClickListener { refreshConfig() }
        } else {
            b.wgkCheckSubscriptionBtn.isVisible = false
        }
    }

    /** Forward physical keyboard events to the TV keyboard when it is visible. */
    fun dispatchKeyEvent(event: android.view.KeyEvent): Boolean =
        tvKeyboard?.takeIf { it.rootView.isVisible }?.handleKey(event) == true

    private fun initWithToken(token: String) {
        val b = binding ?: return
        val auth = AuthStore.getInstance(requireContext())
        b.wgkConnectWithTokenBtn.isEnabled = false
        lifecycleScope.launch {
            try {
                val resp = withContext(Dispatchers.IO) { ApiClient.init(token) }
                auth.saveAccessToken(resp.accessToken)
                auth.saveSubscriptionExpiresAt(resp.subscriptionExpiresAt)
                val config = com.wireguard.config.Config.parse(resp.config.byteInputStream())
                applyConfig(config)
            } catch (_: ApiClient.InvalidTokenException) {
                showSnackbar(getString(R.string.wgk_token_error_format))
            } catch (e: Exception) {
                showSnackbar(getString(R.string.wgk_error_format, e.message ?: ""))
            } finally {
                b.wgkConnectWithTokenBtn.isEnabled = true
            }
        }
    }

    // ── Render ─────────────────────────────────────────────────────────────────

    /**
     * Renders [ui] onto the view tree, skipping whatever the tree already shows.
     *
     * The state flow ticks every couple of seconds for as long as the tunnel is up,
     * and everything on this screen except the traffic figures is a function of the
     * state alone. A full pass re-set six colours, an icon, three progress bars and
     * three tinted dots to the values they already had — inside a container with
     * animateLayoutChanges, so each of those ticks could also start a layout
     * transition. Only the traffic readout is genuinely per-tick work.
     */
    private fun render(ui: TunnelUiState) {
        val b = binding ?: return
        val prev = rendered
        rendered = ui

        if (prev == null || prev.configLoadedAt != ui.configLoadedAt) renderProfile(b, ui)

        if (prev == null || prev.state != ui.state || prev.failure != ui.failure) {
            // Nothing to cross-fade from on the first pass: the view tree has just
            // arrived wearing the layout's resting values.
            renderConnectButton(b, ui, animate = prev != null)
            renderStatusChrome(b, ui)
            renderActionSlot(b, ui.state)
        }
        renderTraffic(b, ui, prev)
    }

    private fun renderProfile(b: TunnelListFragmentBinding, ui: TunnelUiState) {
        b.wgkProfileCard.wgkProfileLoaded.text = formatLoadedAt(ui.configLoadedAt)
    }

    /**
     * Paints the connect control for [ui], cross-fading every part of it at once
     * when [animate].
     *
     * The colours are driven by hand instead of being left to the two selectors in
     * res/color, because a ColorStateList switches in a single frame by
     * construction and cannot be animated at all. The selectors stay the source of
     * truth for *which* colour belongs to each state — they are read here through
     * getColorForState — while the fill, the icon, the three halo rings and the
     * busy arc are blended by one animator so the control moves as one object.
     *
     * That is the whole point, and it is easy to undo by accident. An earlier
     * version animated only the halo and let the fill snap, which in the dark
     * theme read as a flash on disconnect: the resting fill (#222428) is darker
     * than the halo it was leaving behind (wgk_outline #44474E at 0.7 over the
     * background ≈ #34373C), so the button sat dark inside three rings brighter
     * than itself until they caught up. Anything visual added to this control
     * later has to join the animator too, or it will do the same thing.
     */
    private fun renderConnectButton(
        b: TunnelListFragmentBinding,
        ui: TunnelUiState,
        animate: Boolean,
    ) {
        val cb = b.wgkConnectButtonView
        val btn = cb.wgkConnectBtn
        val arc = cb.wgkBusyArc

        btn.contentDescription = getString(when (ui.state) {
            TunnelState.Disconnected -> R.string.wgk_connect_cd_connect
            TunnelState.Connected    -> R.string.wgk_connect_cd_disconnect
            TunnelState.Failed       -> R.string.wgk_connect_cd_retry
            TunnelState.Connecting,
            TunnelState.Handshake,
            TunnelState.Reconnecting -> R.string.wgk_connect_cd_cancel
        })

        val busy = ui.state == TunnelState.Connecting ||
                ui.state == TunnelState.Handshake ||
                ui.state == TunnelState.Reconnecting
        val atRest = ui.state == TunnelState.Disconnected || ui.state == TunnelState.Failed

        // Kept in step with the state even though the fill no longer reads them:
        // they are what the view reports to accessibility, and they keep the
        // selectors meaningful for anyone who looks at res/color first.
        btn.isActivated = busy
        btn.isSelected = ui.state == TunnelState.Connected

        // At rest the button already reads on its own outline, so the halo stays
        // faint; it only comes up once the button is filled and the arc sweeps it.
        val stateSet = buttonStateSet(ui.state)
        val targetBg = selectorColor(R.color.wgk_connect_btn_background_tint, stateSet)
        val targetIcon = selectorColor(R.color.wgk_connect_btn_icon_tint, stateSet)
        val targetRings = if (atRest) RING_ALPHA_REST else RING_ALPHA_ACTIVE
        val targetArc = if (busy) 1f else 0f

        // Cleared before the cancel, so the old animator's end callback can tell
        // that it was superseded and must not run its own teardown.
        val running = buttonAnim
        buttonAnim = null
        running?.cancel()

        // The arc has to be on screen for the whole fade in both directions; only
        // once it has faded out is it taken away. Its own show()/hide() are not
        // used because they set visibility outright, which is precisely the kind of
        // one-frame jump this method exists to avoid.
        val arcWasVisible = arc.isVisible
        if (busy) {
            // Starting from zero only when it is genuinely arriving. An arc caught
            // mid-fade-out already carries the alpha to resume from, and resetting
            // it here would make it blink before fading back in.
            if (!arcWasVisible) arc.alpha = 0f
            arc.isVisible = true
        }

        val fromBg = btn.backgroundTintList?.defaultColor
        val fromIcon = btn.iconTint?.defaultColor
        if (!animate || fromBg == null || fromIcon == null) {
            applyConnectButtonLook(cb, targetBg, targetIcon, targetRings, targetArc)
            arc.isVisible = busy
            return
        }

        val fromRings = floatArrayOf(cb.wgkRingOuter.alpha, cb.wgkRingMid.alpha, cb.wgkRingInner.alpha)
        val fromArc = arc.alpha
        val anim = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = BUTTON_FADE_MS
            interpolator = AccelerateDecelerateInterpolator()
            addUpdateListener { a ->
                val f = a.animatedFraction
                applyConnectButtonLook(
                    cb,
                    ColorUtils.blendARGB(fromBg, targetBg, f),
                    ColorUtils.blendARGB(fromIcon, targetIcon, f),
                    FloatArray(3) { i -> fromRings[i] + (targetRings[i] - fromRings[i]) * f },
                    fromArc + (targetArc - fromArc) * f,
                )
            }
            addListener(object : AnimatorListenerAdapter() {
                override fun onAnimationEnd(animation: Animator) {
                    if (buttonAnim !== animation) return
                    buttonAnim = null
                    if (!busy) arc.isVisible = false
                }
            })
        }
        buttonAnim = anim
        anim.start()
    }

    private fun applyConnectButtonLook(
        cb: ViewWgkConnectButtonBinding,
        bg: Int,
        icon: Int,
        ringAlphas: FloatArray,
        arcAlpha: Float,
    ) {
        cb.wgkConnectBtn.backgroundTintList = ColorStateList.valueOf(bg)
        cb.wgkConnectBtn.iconTint = ColorStateList.valueOf(icon)
        cb.wgkRingOuter.alpha = ringAlphas[0]
        cb.wgkRingMid.alpha = ringAlphas[1]
        cb.wgkRingInner.alpha = ringAlphas[2]
        cb.wgkBusyArc.alpha = arcAlpha
    }

    /** The view state the res/color selectors key on, for the given tunnel state. */
    private fun buttonStateSet(state: TunnelState): IntArray = when (state) {
        TunnelState.Connected -> intArrayOf(android.R.attr.state_selected)
        TunnelState.Connecting,
        TunnelState.Handshake,
        TunnelState.Reconnecting -> intArrayOf(android.R.attr.state_activated)
        TunnelState.Disconnected,
        TunnelState.Failed -> IntArray(0)
    }

    private fun selectorColor(selectorRes: Int, stateSet: IntArray): Int {
        val csl = ContextCompat.getColorStateList(requireContext(), selectorRes)
            ?: return android.graphics.Color.TRANSPARENT
        return csl.getColorForState(stateSet, csl.defaultColor)
    }

    /**
     * The action slot under the button: the hint, the sharing chip, or nothing.
     *
     * The hint is shown only where a tap does something other than what the power
     * icon suggests — cancel while connecting, retry after a failure. At rest and
     * while connected it was the third line reporting one fact (the card below says
     * "VPN off / ready to connect" on its own), so the slot goes to the chip there
     * instead. Sharing needs a live tunnel, so the chip can only appear in Connected
     * and the two never contend for the slot.
     */
    private fun renderActionSlot(b: TunnelListFragmentBinding, state: TunnelState) {
        val key = state to tetherClients
        if (renderedSlotKey == key) return
        renderedSlotKey = key

        val chip = b.wgkTetherChip
        if (chip == null) {
            // TV: no slot and no sharing — the hint is the whole band, and its
            // visibility stays with refreshButtonState/showNoAuthContainer as it
            // always was. Setting it here would put the hint back on top of the
            // no-key screen, which renders on the same state flow.
            renderHeadline(b, state)
            return
        }

        val showChip = tetherClients >= 0 && state == TunnelState.Connected
        chip.isVisible = showChip
        if (showChip) {
            b.wgkTetherChipLabel?.text = getString(R.string.wgk_tether_chip, tetherClients)
            chip.contentDescription = getString(R.string.wgk_tether_chip_cd, tetherClients)
        }

        val showHint = !showChip &&
                state != TunnelState.Connected && state != TunnelState.Disconnected
        b.wgkHeadline.isVisible = showHint
        if (showHint) renderHeadline(b, state)
    }

    private fun renderHeadline(b: TunnelListFragmentBinding, state: TunnelState) {
        b.wgkHeadline.setText(when (state) {
            TunnelState.Disconnected -> R.string.wgk_headline_disconnected
            TunnelState.Connecting   -> R.string.wgk_headline_connecting
            TunnelState.Handshake    -> R.string.wgk_headline_handshake
            TunnelState.Connected    -> R.string.wgk_headline_connected
            TunnelState.Reconnecting -> R.string.wgk_headline_reconnecting
            TunnelState.Failed       -> R.string.wgk_headline_failed
        })
        b.wgkHeadline.setTextColor(ContextCompat.getColor(requireContext(), when (state) {
            TunnelState.Connected    -> R.color.wgk_success
            TunnelState.Reconnecting -> R.color.wgk_warning
            TunnelState.Failed       -> R.color.wgk_error
            else                     -> R.color.wgk_on_surface_variant
        }))
    }

    /**
     * The subtitle for a failure. A terminal failure knows why it happened — the
     * call is gone, the captcha gate stayed shut — and that sentence is the whole
     * difference between "try again" and "stop trying and refresh the config". Only
     * the watchdog's own verdict falls back to the generic network line.
     */
    private fun statusSubRes(ui: TunnelUiState): Int = when (ui.state) {
        TunnelState.Disconnected -> R.string.wgk_status_sub_disconnected
        TunnelState.Connecting   -> R.string.wgk_status_sub_connecting
        TunnelState.Handshake    -> R.string.wgk_status_sub_handshake
        TunnelState.Connected    -> R.string.wgk_status_sub_connected
        TunnelState.Reconnecting -> R.string.wgk_status_sub_reconnecting
        TunnelState.Failed       -> when (ui.failure) {
            TunnelFailure.CallUnavailable  -> R.string.wgk_status_sub_failed_call_gone
            TunnelFailure.CallRequiresAuth -> R.string.wgk_status_sub_failed_call_auth
            TunnelFailure.CaptchaUnsolved  -> R.string.wgk_status_sub_failed_captcha
            TunnelFailure.Credentials      -> R.string.wgk_status_sub_failed_creds
            TunnelFailure.ProxyRestart     -> R.string.wgk_status_sub_failed_restart
            null                           -> R.string.wgk_status_sub_failed
        }
    }

    /** Everything in the status card that follows from the state, not from the tick. */
    private fun renderStatusChrome(b: TunnelListFragmentBinding, ui: TunnelUiState) {
        val sz = b.wgkStatusZone
        val isConnected = ui.state == TunnelState.Connected

        sz.wgkStatusHeadline.setText(when (ui.state) {
            TunnelState.Disconnected -> R.string.wgk_status_disconnected
            TunnelState.Connecting   -> R.string.wgk_status_connecting
            TunnelState.Handshake    -> R.string.wgk_status_handshake
            TunnelState.Connected    -> R.string.wgk_status_connected
            TunnelState.Reconnecting -> R.string.wgk_status_reconnecting
            TunnelState.Failed       -> R.string.wgk_status_failed
        })
        sz.wgkStatusHeadline.setTextColor(ContextCompat.getColor(requireContext(), when (ui.state) {
            TunnelState.Connected    -> R.color.wgk_success
            TunnelState.Reconnecting -> R.color.wgk_warning
            TunnelState.Failed       -> R.color.wgk_error
            else                     -> R.color.wgk_on_surface
        }))
        sz.wgkStatusSub.setText(statusSubRes(ui))

        sz.wgkStatusIcon.setImageResource(when (ui.state) {
            TunnelState.Disconnected -> R.drawable.ic_status_lock_open
            TunnelState.Connecting   -> R.drawable.ic_status_lock
            TunnelState.Handshake    -> R.drawable.ic_status_antenna
            TunnelState.Connected    -> R.drawable.ic_status_shield
            TunnelState.Reconnecting,
            TunnelState.Failed       -> R.drawable.ic_status_warning
        })
        sz.wgkStatusIcon.imageTintList = sz.wgkStatusHeadline.textColors

        // Only shown while connected: without a value underneath, the label was
        // left dangling in the corner and skewed the top of the card. The label now
        // lives in the eyebrow row, so it is toggled separately from the value.
        sz.wgkTrafficContainer.isVisible = isConnected
        sz.wgkRxtxLabel.isVisible = isConnected

        val colorOutline = ContextCompat.getColor(requireContext(), R.color.wgk_outline)
        val colorPrimary = ContextCompat.getColor(requireContext(), R.color.wgk_primary)
        val colorSuccess = ContextCompat.getColor(requireContext(), R.color.wgk_success)
        val colorWarning = ContextCompat.getColor(requireContext(), R.color.wgk_warning)
        val colorError = ContextCompat.getColor(requireContext(), R.color.wgk_error)

        fun progressFor(stage: Int) = when (ui.state) {
            TunnelState.Disconnected,
            TunnelState.Failed       -> 0
            TunnelState.Connecting   -> if (stage == 0) 60 else 0
            TunnelState.Handshake    -> when (stage) { 0 -> 100; 1 -> 60; else -> 0 }
            TunnelState.Connected    -> 100
            // Tunnel + handshake stages were achieved earlier, only routing is broken now.
            TunnelState.Reconnecting -> if (stage < 2) 100 else 60
        }
        fun colorFor(stage: Int) = when (ui.state) {
            TunnelState.Disconnected -> colorOutline
            TunnelState.Failed       -> if (stage == 0) colorError else colorOutline
            TunnelState.Connecting   -> if (stage == 0) colorPrimary else colorOutline
            TunnelState.Handshake    -> when (stage) { 0 -> colorSuccess; 1 -> colorPrimary; else -> colorOutline }
            TunnelState.Connected    -> colorSuccess
            TunnelState.Reconnecting -> if (stage < 2) colorSuccess else colorWarning
        }

        // The stage block is never hidden — progressFor()/colorFor() already render
        // it empty and outlined at rest. Toggling its visibility changed the card's
        // height, which moved the connect button sitting directly above it.
        val segs = listOf(sz.wgkSegTunnel, sz.wgkSegHandshake, sz.wgkSegRouting)
        val dots = listOf(sz.wgkDotTunnel, sz.wgkDotHandshake, sz.wgkDotRouting)
        val lbls = listOf<TextView>(sz.wgkLblTunnel, sz.wgkLblHandshake, sz.wgkLblRouting)
        for (i in 0..2) {
            segs[i].setIndicatorColor(colorFor(i))
            segs[i].setProgressCompat(progressFor(i), true)
            // mutate() is load-bearing: the three dots are inflated from one shape
            // drawable and therefore share a ConstantState, and GradientDrawable
            // writes its tint straight into that shared state. Without this, the
            // last tint in the loop won all three dots — so Handshake showed three
            // outlined dots instead of done/active/idle, and a failed Tunnel stage
            // never went red.
            dots[i].background.mutate().setTint(colorFor(i))
            lbls[i].setTextColor(colorFor(i))
        }
    }

    /** The only genuinely per-tick part of the card: the traffic readout. */
    private fun renderTraffic(
        b: TunnelListFragmentBinding,
        ui: TunnelUiState,
        prev: TunnelUiState?,
    ) {
        if (ui.state != TunnelState.Connected) return
        val sz = b.wgkStatusZone

        if (ui.uptimeSeconds > 0) {
            sz.wgkStatusSub.text = getString(
                R.string.wgk_status_sub_connected_time,
                formatUptime(ui.uptimeSeconds)
            )
        }

        if (prev != null && prev.state == ui.state &&
            prev.rxBytes == ui.rxBytes && prev.txBytes == ui.txBytes) return

        // One unit for both figures, chosen off the larger — mixing MB and GB
        // across the two would misread, and "15734.2 MB" overflows the column.
        val gb = maxOf(ui.rxBytes, ui.txBytes) >= 1_073_741_824L
        val div = if (gb) 1_073_741_824.0 else 1_048_576.0
        sz.wgkRxtxValue.text = getString(R.string.wgk_rxtx_value, ui.rxBytes / div, ui.txBytes / div)
        sz.wgkRxtxUnit.setText(if (gb) R.string.wgk_rxtx_unit_gb else R.string.wgk_rxtx_unit_mb)
    }

    // ── Refresh config ─────────────────────────────────────────────────────────

    private fun refreshConfig(manual: Boolean = true) {
        if (vm.refreshInProgress) return
        val auth = AuthStore.getInstance(requireContext())
        val accessToken = auth.getAccessToken() ?: run {
            showSnackbar(getString(R.string.wgk_no_access_token))
            return
        }
        vm.refreshInProgress = true
        startRefreshAnim()
        lifecycleScope.launch {
            try {
                val resp = withContext(Dispatchers.IO) { ApiClient.getConfig(accessToken) }
                auth.saveSubscriptionExpiresAt(resp.subscriptionExpiresAt)
                auth.saveLastRefreshTime()

                // Manual refresh applies immediately (reconnects if up) and confirms
                // with a snackbar. Auto-refresh only persists the new config — it never
                // reconnects an active tunnel; the change takes effect on the next connect.
                val newHash = sha256(resp.config)
                if (newHash != auth.getLastConfigHash()) {
                    val config = com.wireguard.config.Config.parse(resp.config.byteInputStream())
                    applyConfig(config, reconnect = manual, showFeedback = manual)
                    auth.saveLastConfigHash(newHash)
                } else {
                    refreshButtonState()
                    if (manual) showConfigUpdatedSnackbar(R.string.wgk_config_up_to_date)
                }

                checkForUpdate(resp.latestVersion, resp.downloadUrl)
            } catch (e: ApiClient.UnauthorizedException) {
                AuthStore.getInstance(requireContext()).saveSubscriptionExpiresAt(
                    "1970-01-01T00:00:00Z"  // force expired
                )
                refreshButtonState()
            } catch (e: ApiClient.UpgradeRequiredException) {
                showUpgradeRequired(e.downloadUrl)
            } catch (e: Exception) {
                showSnackbar(getString(R.string.wgk_refresh_error_format, e.message ?: ""))
            } finally {
                stopRefreshAnim()
                vm.refreshInProgress = false
            }
        }
    }

    private fun sha256(s: String): String =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(s.toByteArray())
            .joinToString("") { "%02x".format(it) }

    private fun checkAutoRefresh(auth: AuthStore) {
        if (!auth.isAutoRefreshEnabled()) return
        val elapsed = System.currentTimeMillis() - auth.getLastRefreshTime()
        if (elapsed < 12 * 60 * 60 * 1000L) return
        // The config server may be unreachable while disconnected (DPI block), so
        // fetch through the tunnel: refresh now if a handshake is already up,
        // otherwise defer until we reach Connected (see uiState collector).
        if (vm.uiState.value.state == TunnelState.Connected) refreshConfig(manual = false)
        else vm.pendingAutoRefresh = true
    }

    private fun toggleAutoRefresh() {
        val auth = AuthStore.getInstance(requireContext())
        val enabled = !auth.isAutoRefreshEnabled()
        auth.setAutoRefreshEnabled(enabled)
        if (!enabled) vm.pendingAutoRefresh = false
        val b = binding ?: return
        renderAutoRefreshIcon(b)
        showSnackbar(getString(
            if (enabled) R.string.wgk_auto_refresh_enabled else R.string.wgk_auto_refresh_disabled
        ))
    }

    private fun renderAutoRefreshIcon(b: TunnelListFragmentBinding) {
        val enabled = AuthStore.getInstance(requireContext()).isAutoRefreshEnabled()
        val colorRes = if (enabled) R.color.wgk_primary else R.color.wgk_on_surface_variant
        b.wgkProfileCard.wgkAutoRefreshBtn.apply {
            isSelected = enabled
            contentDescription = getString(
                if (enabled) R.string.wgk_auto_refresh_enabled_cd
                else R.string.wgk_auto_refresh_disabled_cd
            )
            iconTint = ColorStateList.valueOf(
                androidx.core.content.ContextCompat.getColor(requireContext(), colorRes)
            )
        }
    }

    // Shared entry point used by both the refresh button and deeplink import.
    suspend fun applyConfig(
        config: com.wireguard.config.Config,
        reconnect: Boolean = true,
        showFeedback: Boolean = true,
    ) {
        val tunnelManager = Application.getTunnelManager()
        val existing = tunnelManager.getTunnels().firstOrNull { it.name == TUNNEL_NAME }
        if (existing != null) {
            val turnSettings = TurnConfigProcessor.extractTurnSettings(config)
                ?: existing.turnSettings
            val configWithApps = withSplitTunnelApps(config, existing.getConfigAsync())
            // setTunnelConfig does DOWN→save→UP when the tunnel was UP. Bridge the
            // gap in the UI so polling doesn't flip to Failed during the reconnect.
            // With reconnect=false the running tunnel is left as-is (new config takes
            // effect on the next connect), so no UI bridging is needed.
            val wasUp = reconnect && existing.state == Tunnel.State.UP
            if (wasUp) vm.notifyConnecting()
            tunnelManager.setTunnelConfig(existing, configWithApps, turnSettings, reconnect = reconnect)
            if (wasUp) vm.notifyTunnelUp()
        } else {
            tunnelManager.create(TUNNEL_NAME, config)
        }
        recordConfigLoaded()
        refreshButtonState()
        if (showFeedback) showConfigUpdatedSnackbar()
    }

    private fun withSplitTunnelApps(
        newConfig: com.wireguard.config.Config,
        existingConfig: com.wireguard.config.Config,
    ): com.wireguard.config.Config {
        val excluded = existingConfig.`interface`.excludedApplications
        val included = existingConfig.`interface`.includedApplications
        if (excluded.isEmpty() && included.isEmpty()) return newConfig

        val iface = newConfig.`interface`
        val ifaceBuilder = com.wireguard.config.Interface.Builder()
            .addAddresses(iface.addresses)
            .addDnsServers(iface.dnsServers)
            .addDnsSearchDomains(iface.dnsSearchDomains)
            .setKeyPair(iface.keyPair)
        iface.listenPort.ifPresent { ifaceBuilder.setListenPort(it) }
        iface.mtu.ifPresent { ifaceBuilder.setMtu(it) }
        if (excluded.isNotEmpty()) ifaceBuilder.excludeApplications(excluded)
        if (included.isNotEmpty()) ifaceBuilder.includeApplications(included)

        return com.wireguard.config.Config.Builder()
            .setInterface(ifaceBuilder.build())
            .addPeers(newConfig.peers)
            .build()
    }

    private fun startRefreshAnim() {
        val btn = binding?.wgkProfileCard?.wgkRefreshBtn ?: return
        refreshAnim?.cancel()
        refreshAnim = ObjectAnimator.ofFloat(btn, View.ROTATION, 0f, 360f).apply {
            duration = 1_000
            repeatCount = ObjectAnimator.INFINITE
            interpolator = LinearInterpolator()
            start()
        }
    }

    private fun stopRefreshAnim() {
        refreshAnim?.cancel()
        refreshAnim = null
        binding?.wgkProfileCard?.wgkRefreshBtn?.rotation = 0f
    }

    // ── Version check ──────────────────────────────────────────────────────────

    private fun checkForUpdate(latestVersion: String?, downloadUrl: String?) {
        if (updateShownThisSession || latestVersion == null) return
        if (compareVersions(latestVersion, BuildConfig.VERSION_NAME) <= 0) return
        updateShownThisSession = true
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(getString(R.string.wgk_update_available_title, latestVersion))
            .setMessage(getString(R.string.wgk_update_available_message))
            .setPositiveButton(getString(R.string.wgk_update_now)) { _, _ ->
                downloadUrl?.let { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(it))) }
            }
            .setNegativeButton(getString(R.string.wgk_update_later), null)
            .show()
    }

    private fun showUpgradeRequired(downloadUrl: String?) {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(getString(R.string.wgk_upgrade_required_title))
            .setMessage(getString(R.string.wgk_upgrade_required_message))
            .setPositiveButton(getString(R.string.wgk_upgrade_required_action)) { _, _ ->
                downloadUrl?.let { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(it))) }
            }
            .setCancelable(false)
            .show()
    }

    private fun compareVersions(a: String, b: String): Int {
        val ap = a.split(".").map { it.toIntOrNull() ?: 0 }
        val bp = b.split(".").map { it.toIntOrNull() ?: 0 }
        for (i in 0..2) {
            val diff = (ap.getOrElse(i) { 0 }) - (bp.getOrElse(i) { 0 })
            if (diff != 0) return diff
        }
        return 0
    }

    // ── Config timestamp ───────────────────────────────────────────────────────

    fun recordConfigLoaded() {
        val ts = System.currentTimeMillis()
        prefs().edit().putLong(KEY_CONFIG_LOADED_AT, ts).apply()
        val legacy = requireContext().getSharedPreferences(PREFS_CONFIG_LOAD, android.content.Context.MODE_PRIVATE)
        if (legacy !== prefs()) legacy.edit().putLong(KEY_CONFIG_LOADED_AT, ts).apply()
        vm.setConfigLoadedAt(ts)
    }

    private fun syncConfigLoadedAt() {
        lifecycleScope.launch {
            val ts = withContext(Dispatchers.IO) { prefs().getLong(KEY_CONFIG_LOADED_AT, 0L) }
            if (ts != 0L) vm.setConfigLoadedAt(ts)
        }
    }

    private fun prefs(): SharedPreferences {
        _prefs?.let { return it }
        val secure = try {
            val masterKey = MasterKey.Builder(requireContext())
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            EncryptedSharedPreferences.create(
                requireContext(),
                PREFS_CONFIG_LOAD_SECURE,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            )
        } catch (_: Exception) {
            requireContext().getSharedPreferences(PREFS_CONFIG_LOAD, android.content.Context.MODE_PRIVATE)
        }
        migratePrefsIfNeeded(secure)
        _prefs = secure
        return secure
    }

    // One-time migration: move timestamp from legacy plaintext prefs to encrypted prefs.
    private fun migratePrefsIfNeeded(secure: SharedPreferences) {
        val legacy = requireContext().getSharedPreferences(PREFS_CONFIG_LOAD, android.content.Context.MODE_PRIVATE)
        if (legacy === secure) return
        if (!legacy.contains(KEY_CONFIG_LOADED_AT)) return
        val ts = legacy.getLong(KEY_CONFIG_LOADED_AT, 0L)
        if (ts != 0L) secure.edit().putLong(KEY_CONFIG_LOADED_AT, ts).apply()
        legacy.edit().clear().apply()
    }

    private fun formatLoadedAt(ts: Long): String {
        if (ts == 0L) return getString(R.string.wgk_profile_never_loaded)
        val date = Date(ts)
        val today = Date()
        val sdf = SimpleDateFormat("yyyyMMdd", Locale.getDefault())
        return if (sdf.format(date) == sdf.format(today)) {
            getString(R.string.wgk_profile_loaded_at,
                SimpleDateFormat("HH:mm", Locale.getDefault()).format(date))
        } else {
            getString(R.string.wgk_profile_loaded_on,
                SimpleDateFormat("dd.MM HH:mm", Locale.getDefault()).format(date))
        }
    }

    private fun formatUptime(seconds: Long): String {
        val hours = seconds / 3600
        val minutes = (seconds % 3600) / 60
        val remainingSeconds = seconds % 60
        return String.format(Locale.getDefault(), "%02d:%02d:%02d", hours, minutes, remainingSeconds)
    }

    // ── Split tunneling ────────────────────────────────────────────────────────

    private fun openSplitTunnelDialog(forceExcluded: Boolean? = null) {
        lifecycleScope.launch {
            try {
                val tunnel = Application.getTunnelManager().getTunnels()
                    .firstOrNull { it.name == TUNNEL_NAME }
                if (tunnel == null) { showSnackbar(getString(R.string.wgk_config_not_found)); return@launch }
                val config = tunnel.getConfigAsync()
                val proxy = ConfigProxy(config, tunnel.turnSettings)

                var isExcluded = false
                var selectedApps = ArrayList(proxy.`interface`.includedApplications)
                if (selectedApps.isEmpty()) {
                    selectedApps = ArrayList(proxy.`interface`.excludedApplications)
                    if (selectedApps.isNotEmpty()) isExcluded = true
                }
                // Wizard entry: force the requested tab and start from an empty selection.
                if (forceExcluded != null) {
                    isExcluded = forceExcluded
                    selectedApps = ArrayList()
                }

                currentSplitProxy = proxy
                AppListDialogFragment.newInstance(selectedApps, isExcluded)
                    .show(childFragmentManager, null)
            } catch (e: Exception) { showSnackbar(ErrorMessages[e]) }
        }
    }

    private fun saveSplitTunnelApps(proxy: ConfigProxy, newSelections: List<String>, excluded: Boolean) {
        lifecycleScope.launch {
            try {
                val tunnel = Application.getTunnelManager().getTunnels()
                    .firstOrNull { it.name == TUNNEL_NAME }
                if (tunnel == null) { showSnackbar(getString(R.string.wgk_config_not_found)); return@launch }

                if (excluded) {
                    proxy.`interface`.includedApplications.clear()
                    proxy.`interface`.excludedApplications.apply { clear(); addAll(newSelections) }
                } else {
                    proxy.`interface`.excludedApplications.clear()
                    proxy.`interface`.includedApplications.apply { clear(); addAll(newSelections) }
                }

                // setTunnelConfig will bring the tunnel down and back up if it was UP.
                // Reflect that in the UI so the polling job doesn't briefly flip to
                // Failed (stale pollingStartedMs + handshake=0 right after reconnect).
                val wasUp = tunnel.state == Tunnel.State.UP
                if (wasUp) vm.notifyConnecting()

                Application.getTunnelManager().setTunnelConfig(
                    tunnel, proxy.resolve(), tunnel.turnSettings
                )

                if (wasUp) vm.notifyTunnelUp()
                refreshButtonState()
            } catch (e: Exception) {
                vm.notifyTunnelDown()
                showSnackbar(ErrorMessages[e])
            }
        }
    }

    // ── Dev log easter egg ─────────────────────────────────────────────────────

    private fun onLogIconTap() {
        val now = System.currentTimeMillis()
        if (now - logTapLastMs > LOG_TAP_RESET_MS) logTapCount = 0
        logTapLastMs = now
        logTapCount++

        val remaining = LOG_TAPS_REQUIRED - logTapCount
        when {
            remaining <= 0 -> {
                logTapCount = 0
                startActivity(android.content.Intent(requireContext(),
                    com.wireguard.android.activity.LogViewerActivity::class.java))
            }
            remaining <= 3 -> Toast.makeText(
                requireContext(),
                resources.getQuantityString(R.plurals.wgk_log_taps_remaining, remaining, remaining),
                Toast.LENGTH_SHORT
            ).show()
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private fun clipboardToken(): String? {
        val cm = requireContext().getSystemService(android.content.ClipboardManager::class.java)
            ?: return null
        val text = cm.primaryClip?.getItemAt(0)?.coerceToText(requireContext())
            ?.toString() ?: return null
        return TokenFormat.extract(text)
    }

    private fun pasteTokenFromClipboard(b: TunnelListFragmentBinding) {
        val token = clipboardToken()
        if (token != null) {
            b.wgkTokenInput.setText(token)
            b.wgkTokenInput.setSelection(token.length)
            showSnackbar(getString(R.string.wgk_pasted_from_clipboard))
        } else {
            showSnackbar(getString(R.string.wgk_clipboard_no_token))
        }
    }

    private fun showSnackbar(message: CharSequence) {
        val b = binding
        if (b != null) {
            val snackbar = Snackbar.make(b.mainContainer, message, Snackbar.LENGTH_LONG)
            snackbar.setBackgroundTint(ContextCompat.getColor(requireContext(), R.color.wgk_surface_container_high))
            snackbar.setTextColor(ContextCompat.getColor(requireContext(), R.color.wgk_on_surface))
            snackbar.show()
        } else {
            Toast.makeText(activity ?: Application.get(), message, Toast.LENGTH_SHORT).show()
        }
    }

    private fun showConfigUpdatedSnackbar(msgRes: Int = R.string.wgk_config_updated) {
        val b = binding ?: return
        val snackbar = Snackbar.make(b.mainContainer, getString(msgRes), Snackbar.LENGTH_SHORT)
        snackbar.setBackgroundTint(ContextCompat.getColor(requireContext(), R.color.wgk_surface_container_high))
        snackbar.setTextColor(ContextCompat.getColor(requireContext(), R.color.wgk_on_surface))
        val tv = snackbar.view.findViewById<android.widget.TextView>(
            com.google.android.material.R.id.snackbar_text
        )
        val icon = ContextCompat.getDrawable(requireContext(), R.drawable.ic_check)?.mutate()
        icon?.setTint(ContextCompat.getColor(requireContext(), R.color.wgk_success))
        tv?.setCompoundDrawablesRelativeWithIntrinsicBounds(icon, null, null, null)
        tv?.compoundDrawablePadding = resources.getDimensionPixelSize(R.dimen.wgk_snackbar_icon_padding)
        snackbar.show()
    }

    // TV only: the phone screen moved this row to the settings screen, so on a
    // phone every view here is absent and the binding fields are null.
    private fun updateConnectionModeButton() {
        val fr = binding?.wgkFooterRow ?: return
        val isReserve = ConnectionMode.isReserve(requireContext())
        val activeColor = ContextCompat.getColor(requireContext(), R.color.wgk_warning)
        fr.wgkConnectionModeValue?.setText(
            if (isReserve) R.string.wgk_connection_mode_reserve_value
            else R.string.wgk_connection_mode_standard_value
        )
        fr.wgkConnectionModeValue?.setTextColor(
            if (isReserve) activeColor
            else ContextCompat.getColor(requireContext(), R.color.wgk_on_surface)
        )
        fr.wgkConnectionModeIcon?.imageTintList = ColorStateList.valueOf(
            if (isReserve) activeColor
            else ContextCompat.getColor(requireContext(), R.color.wgk_on_surface_variant)
        )
    }

    companion object {
        private const val TAG = "WireGuard/TunnelListFragment"
        private const val TAG_SPLIT_WIZARD = "split_wizard"

        // Halo alphas, outer → inner. The resting set matches the layout defaults.
        private val RING_ALPHA_REST = floatArrayOf(0.10f, 0.16f, 0.24f)
        private val RING_ALPHA_ACTIVE = floatArrayOf(0.28f, 0.45f, 0.70f)

        /** Cross-fade of the whole connect control on a state change. Long enough
         *  to read as a transition, short enough that the tap that caused it still
         *  feels answered immediately. */
        private const val BUTTON_FADE_MS = 180L
    }
}
