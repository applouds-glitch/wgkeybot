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
                        binding?.vpnToggleButton?.isEnabled = true  // разблокируем
                    }
                }
            } else {
                // пользователь отказал
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
                            // Handshake ещё не было
                            statusText = "⏳ Ожидание ответа\nот сервера…"
                            statusColor = android.R.color.darker_gray
                            // продолжаем пульсировать
                        }
                        secondsAgo > 180 -> {
                            // Последний handshake был >3 минут назад — соединение потеряно
                            statusText = "⚠️ Соединение потеряно\nПоследний ответ: ${formatAgo(secondsAgo)} назад"
                            statusColor = R.color.md_theme_light_error
                            startPulseAnimation() // снова пульсируем
                        }
                        else -> {
                            // Всё хорошо
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
                        return@launch  // isEnabled разблокируется в launcher
                    }
                }

                tunnel.setStateAsync(newState)
                updateButtonState()
            } catch (e: Exception) {
                stopPulseAnimation() // ошибка — останавливаем
                showSnackbar(ErrorMessages[e])
            } finally {
                binding?.vpnToggleButton?.isEnabled = true
            }
        }
    }

    private fun updateButtonState() {
        lifecycleScope.launch {
            val binding = binding ?: return@launch
            val tunnel = Application.getTunnelManager().getTunnels()
                .firstOrNull { it.name == TUNNEL_NAME }

            if (tunnel == null) {
                // Скрываем всё связанное с кнопкой
                binding.buttonContainer.visibility = View.GONE
                binding.vpnHintLabel.visibility = View.GONE
                binding.vpnStatusTitle.visibility = View.GONE
                binding.vpnStatusLabel.visibility = View.GONE

                // Показываем подсказку про бота
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
                // Конфиг есть — показываем кнопку, скрываем подсказку
                binding.buttonContainer.visibility = View.VISIBLE
                binding.vpnHintLabel.visibility = View.VISIBLE
                binding.vpnStatusTitle.visibility = View.VISIBLE
                binding.vpnStatusLabel.visibility = View.VISIBLE

                // Скрываем подсказку про бота
                binding.botLinkLabel.visibility = View.GONE
                binding.botLinkButton.visibility = View.GONE


                val isUp = tunnel.state == Tunnel.State.UP
                binding.vpnToggleButton.apply {
//                    text = if (isUp) "Отключить" else "Подключить"
                    backgroundTintList = context.getColorStateList(
                        if (isUp) R.color.md_theme_light_error
                        else R.color.md_theme_light_primary
                    )
                }
                if (isUp) {
                    startStatsPolling(tunnel)
                } else {
                    stopStatsPolling()
                    binding.vpnStatusLabel.text = "Отключено"
                    binding.vpnStatusLabel.setTextColor(
                        requireContext().getColor(android.R.color.white) // или colorOnSurface
                    )
                }


// Цвет кнопки
                binding.vpnToggleButton.backgroundTintList = context?.getColorStateList(
                    if (isUp) R.color.md_theme_light_error
                    else R.color.md_theme_light_primary
                )

// Иконка
                binding.vpnToggleButton.setIconResource(
                    if (isUp) R.drawable.ic_vpn_close
                    else R.drawable.ic_vpn_arrow
                )

// Статус
                binding.vpnStatusLabel.text = when (tunnel.state) {
                    Tunnel.State.UP     -> "Подключено"
                    Tunnel.State.DOWN   -> "Отключено"
                    Tunnel.State.TOGGLE -> "Ожидание"
                    else                -> "Неизвестно"
                }
                binding.vpnStatusLabel.setTextColor(
                    requireContext().getColor(
                        if (isUp) R.color.md_theme_light_primary
                        else android.R.color.white  // или colorOnSurface
                    )
                )

// Подсказка
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