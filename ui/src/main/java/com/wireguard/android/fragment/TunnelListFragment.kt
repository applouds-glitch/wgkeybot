/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.fragment

import android.animation.ObjectAnimator
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.lifecycle.lifecycleScope
import com.google.android.material.snackbar.Snackbar
import com.wireguard.android.Application
import com.wireguard.android.R
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.databinding.TunnelListFragmentBinding
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.updater.SnackbarUpdateShower
import com.wireguard.android.util.ErrorMessages
import com.wireguard.android.viewmodel.ConfigProxy
import kotlinx.coroutines.launch
import androidx.activity.result.contract.ActivityResultContracts
import com.wireguard.android.backend.GoBackend

private const val TUNNEL_NAME = "wgkeybot"

class TunnelListFragment : BaseFragment() {

    private var binding: TunnelListFragmentBinding? = null
    private val snackbarUpdateShower = SnackbarUpdateShower(this)
    private var pendingTunnel: ObservableTunnel? = null

    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val tunnel = pendingTunnel ?: run {
                binding?.vpnToggleButton?.isEnabled = true
                return@registerForActivityResult
            }
            pendingTunnel = null
            if (result.resultCode == android.app.Activity.RESULT_OK) {
                lifecycleScope.launch {
                    try {
                        tunnel.setStateAsync(Tunnel.State.UP)
                        updateButtonState()
                    } catch (e: Exception) {
                        showSnackbar(ErrorMessages[e])
                    } finally {
                        binding?.vpnToggleButton?.isEnabled = true
                    }
                }
            } else {
                stopPulseAnimation()
                binding?.vpnToggleButton?.isEnabled = true
            }
        }

    private var statsJob: kotlinx.coroutines.Job? = null

    private fun startStatsPolling(tunnel: ObservableTunnel) {
        statsJob?.cancel()
        statsJob = lifecycleScope.launch {
            while (true) {
                try {
                    val stats = tunnel.getStatisticsAsync()
                    val binding = binding ?: break

                    val lastHandshakeMs = stats.peers()
                        .mapNotNull { stats.peer(it)?.latestHandshakeEpochMillis }
                        .maxOrNull() ?: 0L

                    val now = System.currentTimeMillis()
                    val secondsAgo = (now - lastHandshakeMs) / 1000

                    val rx = stats.totalRx()
                    val tx = stats.totalTx()

                    val statusText: String
                    val statusColor: Int

                    when {
                        lastHandshakeMs == 0L -> {
                            statusText = "⏳ Ожидание ответа\nот сервера…"
                            statusColor = android.R.color.darker_gray
                        }
                        secondsAgo > 180 -> {
                            statusText = "⚠️ Соединение потеряно\nПоследний ответ: ${formatAgo(secondsAgo)} назад"
                            statusColor = R.color.md_theme_light_error
                            startPulseAnimation()
                        }
                        else -> {
                            statusText = "✓ Соединение установлено\n↓ ${formatBytes(rx)}  ↑ ${formatBytes(tx)}"
                            statusColor = R.color.md_theme_light_primary
                            stopPulseAnimation()
                        }
                    }

                    binding.vpnStatusLabel.text = statusText
                    binding.vpnStatusLabel.setTextColor(requireContext().getColor(statusColor))

                } catch (e: Exception) {
                    // ignore
                }
                kotlinx.coroutines.delay(2000)
            }
        }
    }

    private fun formatAgo(seconds: Long): String {
        return when {
            seconds >= 3600 -> "${seconds / 3600} ч"
            seconds >= 60   -> "${seconds / 60} мин"
            else            -> "$seconds сек"
        }
    }

    private fun stopStatsPolling() {
        statsJob?.cancel()
        statsJob = null
        stopPulseAnimation()
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes >= 1_073_741_824 -> "%.1f GB".format(bytes / 1_073_741_824.0)
            bytes >= 1_048_576     -> "%.1f MB".format(bytes / 1_048_576.0)
            bytes >= 1_024         -> "%.1f KB".format(bytes / 1_024.0)
            else                   -> "$bytes B"
        }
    }

    private var pulseAnimator: ObjectAnimator? = null

    private fun startPulseAnimation() {
        pulseAnimator?.cancel()
        pulseAnimator = ObjectAnimator.ofFloat(binding?.vpnToggleButton, "alpha", 1f, 0.4f).apply {
            duration = 800
            repeatCount = ObjectAnimator.INFINITE
            repeatMode = ObjectAnimator.REVERSE
            interpolator = android.view.animation.AccelerateDecelerateInterpolator()
            start()
        }
    }

    private fun stopPulseAnimation() {
        pulseAnimator?.cancel()
        pulseAnimator = null
        binding?.vpnToggleButton?.alpha = 1f
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        super.onCreateView(inflater, container, savedInstanceState)
        binding = TunnelListFragmentBinding.inflate(inflater, container, false)
        binding?.apply {
            vpnToggleButton.setOnClickListener {
                startPulseAnimation()
                toggleWgKeybot()
            }
            splitTunnelButton.setOnClickListener {
                openSplitTunnelDialog()
            }
            snackbarUpdateShower.attach(mainContainer, vpnToggleButton)
        }
        return binding?.root
    }

    override fun onResume() {
        super.onResume()
        updateButtonState()
    }

    private fun toggleWgKeybot() {
        binding?.vpnToggleButton?.isEnabled = false

        lifecycleScope.launch {
            try {
                val tunnel = Application.getTunnelManager().getTunnels()
                    .firstOrNull { it.name == TUNNEL_NAME }
                if (tunnel == null) {
                    showSnackbar("Конфиг wgkeybot не найден.")
                    binding?.vpnToggleButton?.isEnabled = true
                    return@launch
                }

                val newState = if (tunnel.state == Tunnel.State.UP) Tunnel.State.DOWN else Tunnel.State.UP

                if (newState == Tunnel.State.UP && Application.getBackend() is GoBackend) {
                    val intent = GoBackend.VpnService.prepare(requireContext())
                    if (intent != null) {
                        pendingTunnel = tunnel
                        vpnPermissionLauncher.launch(intent)
                        return@launch
                    }
                }

                tunnel.setStateAsync(newState)
                updateButtonState()
            } catch (e: Exception) {
                stopPulseAnimation()
                showSnackbar(ErrorMessages[e])
            } finally {
                binding?.vpnToggleButton?.isEnabled = true
            }
        }
    }

    // ── Split tunneling ────────────────────────────────────────────────────────

    private fun openSplitTunnelDialog() {
        lifecycleScope.launch {
            try {
                val tunnel = Application.getTunnelManager().getTunnels()
                    .firstOrNull { it.name == TUNNEL_NAME }
                if (tunnel == null) {
                    showSnackbar("Конфиг wgkeybot не найден.")
                    return@launch
                }
                val config = tunnel.getConfigAsync()
                val proxy = ConfigProxy(config, tunnel.turnSettings)

                var isExcluded = true
                var selectedApps = ArrayList(proxy.`interface`.excludedApplications)
                if (selectedApps.isEmpty()) {
                    selectedApps = ArrayList(proxy.`interface`.includedApplications)
                    if (selectedApps.isNotEmpty()) isExcluded = false
                }

                childFragmentManager.setFragmentResultListener(
                    AppListDialogFragment.REQUEST_SELECTION,
                    viewLifecycleOwner
                ) { _, bundle ->
                    val newSelections = bundle.getStringArray(AppListDialogFragment.KEY_SELECTED_APPS)
                        ?: return@setFragmentResultListener
                    val excluded = bundle.getBoolean(AppListDialogFragment.KEY_IS_EXCLUDED)
                    saveSplitTunnelApps(proxy, newSelections.toList(), excluded)
                }

                AppListDialogFragment.newInstance(selectedApps, isExcluded)
                    .show(childFragmentManager, null)

            } catch (e: Exception) {
                showSnackbar(ErrorMessages[e])
            }
        }
    }

    private fun saveSplitTunnelApps(proxy: ConfigProxy, newSelections: List<String>, excluded: Boolean) {
        lifecycleScope.launch {
            try {
                val tunnel = Application.getTunnelManager().getTunnels()
                    .firstOrNull { it.name == TUNNEL_NAME }
                if (tunnel == null) {
                    showSnackbar("Конфиг wgkeybot не найден.")
                    return@launch
                }

                if (excluded) {
                    proxy.`interface`.includedApplications.clear()
                    proxy.`interface`.excludedApplications.apply {
                        clear()
                        addAll(newSelections)
                    }
                } else {
                    proxy.`interface`.excludedApplications.clear()
                    proxy.`interface`.includedApplications.apply {
                        clear()
                        addAll(newSelections)
                    }
                }

                val newConfig = proxy.resolve()
                val newTurnSettings = proxy.resolveTurnSettings()
                Application.getTunnelManager().setTunnelConfig(tunnel, newConfig, newTurnSettings)

                updateButtonState()
                showSnackbar(
                    when {
                        newSelections.isEmpty() -> "Все приложения через VPN"
                        excluded -> "Исключено приложений: ${newSelections.size}"
                        else -> "Только ${newSelections.size} прил. через VPN"
                    }
                )
            } catch (e: Exception) {
                showSnackbar(ErrorMessages[e])
            }
        }
    }

    // ── UI state ───────────────────────────────────────────────────────────────

    private fun updateButtonState() {
        lifecycleScope.launch {
            val binding = binding ?: return@launch
            val tunnel = Application.getTunnelManager().getTunnels()
                .firstOrNull { it.name == TUNNEL_NAME }

            if (tunnel == null) {
                binding.buttonContainer.visibility = View.GONE
                binding.vpnHintLabel.visibility = View.GONE
                binding.vpnStatusTitle.visibility = View.GONE
                binding.vpnStatusLabel.visibility = View.GONE
                binding.splitTunnelButton.visibility = View.GONE

                binding.botLinkLabel.visibility = View.VISIBLE
                binding.botLinkButton.visibility = View.VISIBLE
                binding.botLinkButton.setOnClickListener {
                    val intent = android.content.Intent(
                        android.content.Intent.ACTION_VIEW,
                        android.net.Uri.parse("https://t.me/wg_key_bot")
                    )
                    startActivity(intent)
                }
                stopStatsPolling()
            } else {
                binding.buttonContainer.visibility = View.VISIBLE
                binding.vpnHintLabel.visibility = View.VISIBLE
                binding.vpnStatusTitle.visibility = View.VISIBLE
                binding.vpnStatusLabel.visibility = View.VISIBLE
                binding.splitTunnelButton.visibility = View.VISIBLE

                binding.botLinkLabel.visibility = View.GONE
                binding.botLinkButton.visibility = View.GONE

                // Текст кнопки split tunneling
                val config = tunnel.getConfigAsync()
                binding.splitTunnelButton.text = when {
                    config.`interface`.includedApplications.isNotEmpty() ->
                        "Только: ${config.`interface`.includedApplications.size} прил."
                    config.`interface`.excludedApplications.isNotEmpty() ->
                        "Исключено: ${config.`interface`.excludedApplications.size} прил."
                    else -> "Раздельное туннелирование"
                }

                val isUp = tunnel.state == Tunnel.State.UP
                if (isUp) {
                    startStatsPolling(tunnel)
                } else {
                    stopStatsPolling()
                    binding.vpnStatusLabel.text = "Отключено"
                    binding.vpnStatusLabel.setTextColor(
                        requireContext().getColor(android.R.color.white)
                    )
                }

                binding.vpnToggleButton.backgroundTintList = context?.getColorStateList(
                    if (isUp) R.color.md_theme_light_error
                    else R.color.md_theme_light_primary
                )

                binding.vpnToggleButton.setIconResource(
                    if (isUp) R.drawable.ic_vpn_close
                    else R.drawable.ic_vpn_arrow
                )

                binding.vpnStatusLabel.text = when (tunnel.state) {
                    Tunnel.State.UP     -> "Подключено"
                    Tunnel.State.DOWN   -> "Отключено"
                    Tunnel.State.TOGGLE -> "Ожидание"
                    else                -> "Неизвестно"
                }
                binding.vpnStatusLabel.setTextColor(
                    requireContext().getColor(
                        if (isUp) R.color.md_theme_light_primary
                        else android.R.color.white
                    )
                )

                binding.vpnHintLabel.text = if (isUp) "Нажмите для отключения" else "Нажмите для подключения"
            }
        }
    }

    fun refreshState() {
        updateButtonState()
    }

    override fun onDestroyView() {
        statsJob?.cancel()
        stopPulseAnimation()
        binding = null
        super.onDestroyView()
    }

    override fun onSelectedTunnelChanged(oldTunnel: ObservableTunnel?, newTunnel: ObservableTunnel?) = Unit

    private fun showSnackbar(message: CharSequence) {
        val b = binding
        if (b != null)
            Snackbar.make(b.mainContainer, message, Snackbar.LENGTH_LONG).show()
        else
            Toast.makeText(activity ?: Application.get(), message, Toast.LENGTH_SHORT).show()
    }

    companion object {
        private const val TAG = "WireGuard/TunnelListFragment"
    }
}