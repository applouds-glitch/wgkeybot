/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.fragment

import android.animation.ObjectAnimator
import android.content.SharedPreferences
import android.content.res.Configuration
import android.os.Bundle
import android.view.ContextThemeWrapper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.LinearInterpolator
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.core.view.isVisible
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.snackbar.Snackbar
import com.wireguard.android.Application
import com.wireguard.android.BuildConfig
import com.wireguard.android.R
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.databinding.TunnelListFragmentBinding
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.updater.SnackbarUpdateShower
import com.wireguard.android.util.ConfigFetcher
import com.wireguard.android.util.ErrorMessages
import com.wireguard.android.viewmodel.ConfigProxy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.activity.result.contract.ActivityResultContracts
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.TurnBackend
import com.wireguard.android.turn.TurnConfigProcessor
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private const val TUNNEL_NAME = "wgkeybot"
private const val PREFS_TURN_MODE = "turn_mode"
private const val KEY_STABILITY_MODE = "stability_mode"
private const val PREFS_CONFIG_LOAD = "config_load_prefs"          // legacy (migration only)
private const val PREFS_CONFIG_LOAD_SECURE = "config_load_secure"  // encrypted
private const val KEY_CONFIG_LOADED_AT = "config_loaded_at"
private const val KEY_CONFIG_TOKEN = "config_token"

class TunnelListFragment : BaseFragment() {

    private var binding: TunnelListFragmentBinding? = null
    private val vm: TunnelListViewModel by viewModels()
    private val snackbarUpdateShower = SnackbarUpdateShower(this)
    private var pendingTunnel: ObservableTunnel? = null
    private var refreshAnim: ObjectAnimator? = null
    private var _prefs: SharedPreferences? = null

    private var currentSplitProxy: ConfigProxy? = null

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
                        tunnel.setStateAsync(Tunnel.State.UP)
                        vm.notifyTunnelUp()
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

        // Force dark theme context so MDC inherited styles (ripples, overlays) are dark.
        // Must use ContextThemeWrapper + applyOverrideConfiguration, not createConfigurationContext,
        // because createConfigurationContext drops the theme and MDC ThemeEnforcement crashes.
        val darkConfig = Configuration(resources.configuration).apply {
            uiMode = (uiMode and Configuration.UI_MODE_NIGHT_MASK.inv()) or
                    Configuration.UI_MODE_NIGHT_YES
        }
        val darkContext = ContextThemeWrapper(requireContext(), requireContext().theme).also {
            it.applyOverrideConfiguration(darkConfig)
        }
        val darkInflater = inflater.cloneInContext(darkContext)

        binding = TunnelListFragmentBinding.inflate(darkInflater, container, false)
        binding?.apply {
            wgkConnectButtonView.wgkConnectBtn.setOnClickListener { toggleWgKeybot() }
            wgkFooterRow.wgkSplitBtn.setOnClickListener { openSplitTunnelDialog() }
            wgkProfileCard.wgkRefreshBtn.setOnClickListener { refreshConfig() }
            wgkProfileCard.wgkProfileIcon.setOnClickListener { onLogIconTap() }
            snackbarUpdateShower.attach(mainContainer, wgkConnectButtonView.wgkConnectBtn)
        }

        // Register once so stale pending results from previous dialogs don't re-fire.
        // currentSplitProxy is null until the dialog is actually open, so any stale result is ignored.
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

        syncConfigLoadedAt()

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                vm.uiState.collect { render(it) }
            }
        }

        return binding?.root
    }

    override fun onResume() {
        super.onResume()
        refreshButtonState()
    }

    override fun onDestroyView() {
        refreshAnim?.cancel()
        refreshAnim = null
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
                    showSnackbar("Конфиг wgkeybot не найден.")
                    return@launch
                }

                val newState = if (tunnel.state == Tunnel.State.UP || vm.isConnecting)
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
                } else if (vm.isConnecting) {
                    vm.cancelledByUser = true
                    withContext(Dispatchers.IO) { TurnBackend.wgTurnProxyStop() }
                }

                tunnel.setStateAsync(newState)
                if (newState == Tunnel.State.UP) vm.notifyTunnelUp() else vm.notifyTunnelDown()
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
            val binding = binding ?: return@launch
            val tunnel = Application.getTunnelManager().getTunnels()
                .firstOrNull { it.name == TUNNEL_NAME }

            if (tunnel == null) {
                vm.notifyTunnelDown()
                binding.wgkNoConfigContainer.isVisible = true
                binding.wgkProfileCard.root.isVisible = false
                binding.wgkConnectButtonView.root.isVisible = false
                binding.wgkHeadline.isVisible = false
                binding.wgkStatusZone.root.isVisible = false
                binding.wgkFooterRow.root.isVisible = false
                binding.wgkBotLinkBtn.setOnClickListener {
                    startActivity(
                        android.content.Intent(
                            android.content.Intent.ACTION_VIEW,
                            android.net.Uri.parse("https://t.me/wg_key_bot")
                        )
                    )
                }
                return@launch
            }

            binding.wgkNoConfigContainer.isVisible = false
            binding.wgkProfileCard.root.isVisible = true
            binding.wgkConnectButtonView.root.isVisible = true
            binding.wgkHeadline.isVisible = true
            binding.wgkStatusZone.root.isVisible = true
            binding.wgkFooterRow.root.isVisible = true

            // Resume polling without resetting uptime if already running (e.g. after rotation)
            if (tunnel.state == Tunnel.State.UP && !vm.isConnecting) {
                vm.ensurePollingActive()
            }

            // Split tunneling button label
            val config = tunnel.getConfigAsync()
            binding.wgkFooterRow.wgkSplitBtn.text = when {
                config.`interface`.includedApplications.isNotEmpty() ->
                    "Только: ${config.`interface`.includedApplications.size} прил."
                config.`interface`.excludedApplications.isNotEmpty() ->
                    "Исключено: ${config.`interface`.excludedApplications.size} прил."
                else -> getString(R.string.wgk_action_split_tunneling)
            }
        }
    }

    // ── Render ─────────────────────────────────────────────────────────────────

    private fun render(ui: TunnelUiState) {
        val b = binding ?: return
        renderProfile(b, ui)
        renderConnectButton(b, ui)
        renderHeadline(b, ui)
        renderStatusZone(b, ui)
    }

    private fun renderProfile(b: TunnelListFragmentBinding, ui: TunnelUiState) {
        b.wgkProfileCard.wgkProfileLoaded.text = formatLoadedAt(ui.configLoadedAt)
    }

    private fun renderConnectButton(b: TunnelListFragmentBinding, ui: TunnelUiState) {
        val btn = b.wgkConnectButtonView.wgkConnectBtn
        val arc = b.wgkConnectButtonView.wgkBusyArc
        when (ui.state) {
            TunnelState.Disconnected -> {
                btn.isActivated = false; btn.isSelected = false; arc.isVisible = false
            }
            TunnelState.Connecting,
            TunnelState.Handshake -> {
                btn.isActivated = true;  btn.isSelected = false; arc.isVisible = true
            }
            TunnelState.Connected -> {
                btn.isActivated = false; btn.isSelected = true;  arc.isVisible = false
            }
        }
    }

    private fun renderHeadline(b: TunnelListFragmentBinding, ui: TunnelUiState) {
        b.wgkHeadline.setText(when (ui.state) {
            TunnelState.Disconnected -> R.string.wgk_headline_disconnected
            TunnelState.Connecting   -> R.string.wgk_headline_connecting
            TunnelState.Handshake    -> R.string.wgk_headline_handshake
            TunnelState.Connected    -> R.string.wgk_headline_connected
        })
        b.wgkHeadline.setTextColor(ContextCompat.getColor(requireContext(),
            if (ui.state == TunnelState.Connected) R.color.wgk_success
            else R.color.wgk_on_surface_variant
        ))
    }

    private fun renderStatusZone(b: TunnelListFragmentBinding, ui: TunnelUiState) {
        val sz = b.wgkStatusZone
        val isConnected = ui.state == TunnelState.Connected

        // Headline + sub
        sz.wgkStatusHeadline.setText(when (ui.state) {
            TunnelState.Disconnected -> R.string.wgk_status_disconnected
            TunnelState.Connecting   -> R.string.wgk_status_connecting
            TunnelState.Handshake    -> R.string.wgk_status_handshake
            TunnelState.Connected    -> R.string.wgk_status_connected
        })
        sz.wgkStatusHeadline.setTextColor(ContextCompat.getColor(requireContext(),
            if (isConnected) R.color.wgk_success else R.color.wgk_on_surface))
        sz.wgkStatusSub.setText(when (ui.state) {
            TunnelState.Disconnected -> R.string.wgk_status_sub_disconnected
            TunnelState.Connecting   -> R.string.wgk_status_sub_connecting
            TunnelState.Handshake    -> R.string.wgk_status_sub_handshake
            TunnelState.Connected    -> R.string.wgk_status_sub_connected
        })

        // RX/TX
        sz.wgkRxtxLabel.setText(if (isConnected) R.string.wgk_rxtx_label else R.string.wgk_wireguard_label)
        sz.wgkRxtxValue.isVisible = isConnected
        if (isConnected) {
            sz.wgkRxtxValue.text = getString(R.string.wgk_rxtx_value,
                ui.rxBytes / 1_048_576.0, ui.txBytes / 1_048_576.0)
        }

        // Colors
        val colorOutline = ContextCompat.getColor(requireContext(), R.color.wgk_outline)
        val colorPrimary = ContextCompat.getColor(requireContext(), R.color.wgk_primary)
        val colorSuccess = ContextCompat.getColor(requireContext(), R.color.wgk_success)

        fun progressFor(stage: Int) = when (ui.state) {
            TunnelState.Disconnected -> 0
            TunnelState.Connecting   -> if (stage == 0) 60 else 0
            TunnelState.Handshake    -> when (stage) { 0 -> 100; 1 -> 60; else -> 0 }
            TunnelState.Connected    -> 100
        }
        fun colorFor(stage: Int) = when (ui.state) {
            TunnelState.Disconnected -> colorOutline
            TunnelState.Connecting   -> if (stage == 0) colorPrimary else colorOutline
            TunnelState.Handshake    -> when (stage) { 0 -> colorSuccess; 1 -> colorPrimary; else -> colorOutline }
            TunnelState.Connected    -> colorSuccess
        }

        val segs = listOf(sz.wgkSegTunnel, sz.wgkSegHandshake, sz.wgkSegRouting)
        val dots = listOf(sz.wgkDotTunnel, sz.wgkDotHandshake, sz.wgkDotRouting)
        val lbls = listOf<TextView>(sz.wgkLblTunnel, sz.wgkLblHandshake, sz.wgkLblRouting)

        for (i in 0..2) {
            segs[i].setIndicatorColor(colorFor(i))
            segs[i].setProgressCompat(progressFor(i), true)
            dots[i].background.setTint(colorFor(i))
            lbls[i].setTextColor(colorFor(i))
        }
    }

    // ── Refresh config ─────────────────────────────────────────────────────────

    private fun refreshConfig() {
        val token = loadToken() ?: run {
            showSnackbar("Токен не найден. Переоткройте ссылку из бота.")
            return
        }
        startRefreshAnim()
        lifecycleScope.launch {
            try {
                val configText = withContext(Dispatchers.IO) { ConfigFetcher.fetch(token) }
                val config = com.wireguard.config.Config.parse(configText.byteInputStream())
                applyConfig(token, config)
            } catch (e: Exception) {
                showSnackbar("Ошибка обновления: ${e.message}")
            } finally {
                stopRefreshAnim()
            }
        }
    }

    // Shared entry point used by both the refresh button and deeplink import.
    suspend fun applyConfig(token: String, config: com.wireguard.config.Config) {
        val tunnelManager = Application.getTunnelManager()
        val existing = tunnelManager.getTunnels().firstOrNull { it.name == TUNNEL_NAME }
        if (existing != null) {
            val turnSettings = TurnConfigProcessor.extractTurnSettings(config)
                ?: existing.turnSettings
            // Preserve split tunnel app selections — they are a client-side setting
            // not present in the server config, so we carry them over from the current config.
            val configWithApps = withSplitTunnelApps(config, existing.getConfigAsync())
            tunnelManager.setTunnelConfig(existing, configWithApps, turnSettings)
        } else {
            tunnelManager.create(TUNNEL_NAME, config)
        }
        saveToken(token)
        recordConfigLoaded()
        refreshButtonState()
        showConfigUpdatedSnackbar()
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

    // ── Config timestamp ───────────────────────────────────────────────────────

    fun recordConfigLoaded() {
        val ts = System.currentTimeMillis()
        prefs().edit().putLong(KEY_CONFIG_LOADED_AT, ts).apply()
        val legacy = requireContext().getSharedPreferences(PREFS_CONFIG_LOAD, android.content.Context.MODE_PRIVATE)
        if (legacy !== prefs()) legacy.edit().putLong(KEY_CONFIG_LOADED_AT, ts).apply()
        vm.setConfigLoadedAt(ts)
    }

    fun saveToken(token: String) {
        prefs().edit().putString(KEY_CONFIG_TOKEN, token).apply()
        // Dual-write to legacy so it survives an ESP keystore failure on next launch.
        val legacy = requireContext().getSharedPreferences(PREFS_CONFIG_LOAD, android.content.Context.MODE_PRIVATE)
        if (legacy !== prefs()) legacy.edit().putString(KEY_CONFIG_TOKEN, token).apply()
    }

    private fun loadToken(): String? {
        val token = prefs().getString(KEY_CONFIG_TOKEN, null)
        if (token != null) return token
        // ESP may have failed; fall back to legacy plaintext backup.
        val legacy = requireContext().getSharedPreferences(PREFS_CONFIG_LOAD, android.content.Context.MODE_PRIVATE)
        return legacy.getString(KEY_CONFIG_TOKEN, null)
    }

    private fun syncConfigLoadedAt() {
        val ts = prefs().getLong(KEY_CONFIG_LOADED_AT, 0L)
        if (ts != 0L) vm.setConfigLoadedAt(ts)
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
            // Keystore unavailable — fall back to plain prefs (e.g. emulators without HSM)
            requireContext().getSharedPreferences(PREFS_CONFIG_LOAD, android.content.Context.MODE_PRIVATE)
        }
        migratePrefsIfNeeded(secure)
        _prefs = secure
        return secure
    }

    // One-time migration: move token + timestamp from legacy plaintext prefs to encrypted prefs.
    private fun migratePrefsIfNeeded(secure: SharedPreferences) {
        val legacy = requireContext().getSharedPreferences(PREFS_CONFIG_LOAD, android.content.Context.MODE_PRIVATE)
        // If ESP failed to init, secure IS legacy — skip migration to avoid self-clearing.
        if (legacy === secure) return
        if (!legacy.contains(KEY_CONFIG_TOKEN) && !legacy.contains(KEY_CONFIG_LOADED_AT)) return
        val editor = secure.edit()
        legacy.getString(KEY_CONFIG_TOKEN, null)?.let { editor.putString(KEY_CONFIG_TOKEN, it) }
        val ts = legacy.getLong(KEY_CONFIG_LOADED_AT, 0L)
        if (ts != 0L) editor.putLong(KEY_CONFIG_LOADED_AT, ts)
        editor.apply()
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

    // ── Split tunneling ────────────────────────────────────────────────────────

    private fun openSplitTunnelDialog() {
        lifecycleScope.launch {
            try {
                val tunnel = Application.getTunnelManager().getTunnels()
                    .firstOrNull { it.name == TUNNEL_NAME }
                if (tunnel == null) { showSnackbar("Конфиг wgkeybot не найден."); return@launch }
                val config = tunnel.getConfigAsync()
                val proxy = ConfigProxy(config, tunnel.turnSettings)

                var isExcluded = false
                var selectedApps = ArrayList(proxy.`interface`.includedApplications)
                if (selectedApps.isEmpty()) {
                    selectedApps = ArrayList(proxy.`interface`.excludedApplications)
                    if (selectedApps.isNotEmpty()) isExcluded = true
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
                if (tunnel == null) { showSnackbar("Конфиг wgkeybot не найден."); return@launch }

                if (excluded) {
                    proxy.`interface`.includedApplications.clear()
                    proxy.`interface`.excludedApplications.apply { clear(); addAll(newSelections) }
                } else {
                    proxy.`interface`.excludedApplications.clear()
                    proxy.`interface`.includedApplications.apply { clear(); addAll(newSelections) }
                }

                // Use tunnel.turnSettings directly to avoid TurnSettingsProxy validation
                // throwing BadConfigException and silently dropping the split-tunnel save.
                Application.getTunnelManager().setTunnelConfig(
                    tunnel, proxy.resolve(), tunnel.turnSettings
                )
                refreshButtonState()
            } catch (e: Exception) { showSnackbar(ErrorMessages[e]) }
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

    private fun showSnackbar(message: CharSequence) {
        val b = binding
        if (b != null) Snackbar.make(b.mainContainer, message, Snackbar.LENGTH_LONG).show()
        else Toast.makeText(activity ?: Application.get(), message, Toast.LENGTH_SHORT).show()
    }

    private fun showConfigUpdatedSnackbar() {
        val b = binding ?: return
        val snackbar = Snackbar.make(b.mainContainer, "Конфиг обновлён", Snackbar.LENGTH_SHORT)
        snackbar.setBackgroundTint(ContextCompat.getColor(requireContext(), R.color.wgk_surface_container_high))
        snackbar.setTextColor(ContextCompat.getColor(requireContext(), R.color.wgk_on_surface))
        val tv = snackbar.view.findViewById<android.widget.TextView>(
            com.google.android.material.R.id.snackbar_text
        )
        val icon = ContextCompat.getDrawable(requireContext(), R.drawable.ic_check)?.mutate()
        icon?.setTint(ContextCompat.getColor(requireContext(), R.color.wgk_success))
        tv?.setCompoundDrawablesRelativeWithIntrinsicBounds(icon, null, null, null)
        tv?.compoundDrawablePadding = resources.getDimensionPixelSize(R.dimen.wgk_snackbar_icon_padding)
        val params = snackbar.view.layoutParams as androidx.coordinatorlayout.widget.CoordinatorLayout.LayoutParams
        params.gravity = android.view.Gravity.TOP
        snackbar.view.layoutParams = params
        snackbar.show()
    }

    companion object {
        private const val TAG = "WireGuard/TunnelListFragment"
    }
}
