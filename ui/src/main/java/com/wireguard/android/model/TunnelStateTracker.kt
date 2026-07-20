/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.model

import android.content.Context
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import androidx.databinding.Observable
import androidx.databinding.ObservableList
import com.wireguard.android.Application
import com.wireguard.android.BR
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.fragment.TunnelState
import com.wireguard.android.fragment.TunnelUiState
import com.wireguard.android.util.ScreenStateMonitor
import com.wireguard.android.util.applicationScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch


/**
 * Single source of truth for the user-facing tunnel state (Connecting / Handshake /
 * Connected / Reconnecting / Failed). Lives in the Application scope so both the
 * fragment ViewModel and the home-screen widget can subscribe to the same state.
 *
 * The tracker watches the named tunnel; whenever [Tunnel.State.UP] it runs a stats
 * poll loop and derives the UI state from the last handshake timestamp. A one-shot
 * haptic fires on the transition into [TunnelState.Connected] so the widget feels
 * the same as the app on a successful connect.
 */
class TunnelStateTracker(private val context: Context) {

    private val _uiState = MutableStateFlow(TunnelUiState())
    val uiState: StateFlow<TunnelUiState> = _uiState.asStateFlow()

    private var trackedTunnel: ObservableTunnel? = null
    private var pollingJob: Job? = null
    private var firstHandshakeMs = 0L
    private var pollingStartedMs = 0L
    private var lastEmittedState: TunnelState = TunnelState.Disconnected

    private val tunnelStateCallback = object : Observable.OnPropertyChangedCallback() {
        override fun onPropertyChanged(sender: Observable, propertyId: Int) {
            if (sender != trackedTunnel) {
                sender.removeOnPropertyChangedCallback(this)
                return
            }
            if (propertyId != 0 && propertyId != BR.state) return
            syncWithTunnel()
        }
    }

    private val listCallback = object : ObservableList.OnListChangedCallback<ObservableList<ObservableTunnel>>() {
        override fun onChanged(sender: ObservableList<ObservableTunnel>) = retrack(sender)
        override fun onItemRangeChanged(sender: ObservableList<ObservableTunnel>, p: Int, c: Int) = retrack(sender)
        override fun onItemRangeInserted(sender: ObservableList<ObservableTunnel>, p: Int, c: Int) = retrack(sender)
        override fun onItemRangeMoved(sender: ObservableList<ObservableTunnel>, f: Int, t: Int, c: Int) = retrack(sender)
        override fun onItemRangeRemoved(sender: ObservableList<ObservableTunnel>, p: Int, c: Int) = retrack(sender)
    }

    fun attach() {
        applicationScope.launch {
            val tunnels = Application.getTunnelManager().getTunnels()
            tunnels.addOnListChangedCallback(listCallback)
            retrack(tunnels)
        }
    }

    /** Immediately reflect a user-initiated connect tap before tunnel.state has changed. */
    fun signalUserConnect() {
        if (_uiState.value.state != TunnelState.Connecting) {
            emit(_uiState.value.copy(state = TunnelState.Connecting))
        }
    }

    /** Immediately reflect a user-initiated disconnect, stopping polling and resetting counters. */
    fun signalUserDisconnect() {
        stopPolling()
        emit(TunnelUiState(configLoadedAt = _uiState.value.configLoadedAt))
    }

    fun setConfigLoadedAt(ts: Long) {
        emit(_uiState.value.copy(configLoadedAt = ts))
    }

    fun currentConfigLoadedAt(): Long = _uiState.value.configLoadedAt

    private fun retrack(tunnels: ObservableList<ObservableTunnel>) {
        val newTunnel = tunnels.firstOrNull { it.name == TUNNEL_NAME }
        if (newTunnel != trackedTunnel) {
            trackedTunnel?.removeOnPropertyChangedCallback(tunnelStateCallback)
            trackedTunnel = newTunnel
            trackedTunnel?.addOnPropertyChangedCallback(tunnelStateCallback)
        }
        syncWithTunnel()
    }

    private fun syncWithTunnel() {
        val tunnel = trackedTunnel
        if (tunnel == null || tunnel.state != Tunnel.State.UP) {
            // Tunnel was deleted, never imported, or just turned DOWN.
            if (pollingJob?.isActive == true || _uiState.value.state != TunnelState.Disconnected) {
                stopPolling()
                emit(TunnelUiState(configLoadedAt = _uiState.value.configLoadedAt))
            }
            return
        }
        if (pollingJob?.isActive == true) return
        startPolling(tunnel)
    }

    private fun startPolling(tunnel: ObservableTunnel) {
        stopPolling()
        firstHandshakeMs = 0L
        pollingStartedMs = System.currentTimeMillis()

        pollingJob = applicationScope.launch(Dispatchers.IO) {
            while (isActive) {
                // Screen off → no UI surface is looking (the widget included, and a
                // state change while parked is re-rendered by the first poll after
                // wake). Park instead of a JNI stats call every 2s all night. This
                // is display-only: the tunnel, keepalives and the handshake watchdog
                // are untouched. Resumes (and polls immediately) when the screen
                // turns on; a tunnel-down while parked cancels this job as usual.
                ScreenStateMonitor.screenOn.first { it }
                if (tunnel.state != Tunnel.State.UP) {
                    emit(TunnelUiState(configLoadedAt = _uiState.value.configLoadedAt))
                    break
                }
                try {
                    val stats = tunnel.getStatisticsAsync()
                    val lastHandshakeMs = stats.peers()
                        .mapNotNull { stats.peer(it)?.latestHandshakeEpochMillis }
                        .maxOrNull() ?: 0L
                    val rx = stats.totalRx()
                    val tx = stats.totalTx()
                    val now = System.currentTimeMillis()
                    val newState = when {
                        lastHandshakeMs == 0L -> {
                            if (now - pollingStartedMs > INITIAL_HANDSHAKE_TIMEOUT_MS) TunnelState.Failed
                            else TunnelState.Connecting
                        }
                        (now - lastHandshakeMs) / 1000 > HANDSHAKE_STALE_SECONDS -> TunnelState.Reconnecting
                        firstHandshakeMs == 0L || (now - firstHandshakeMs) / 1000 < HANDSHAKE_DISPLAY_SECONDS -> {
                            if (firstHandshakeMs == 0L) firstHandshakeMs = now
                            TunnelState.Handshake
                        }
                        else -> TunnelState.Connected
                    }
                    emit(_uiState.value.copy(state = newState, rxBytes = rx, txBytes = tx))
                } catch (_: Exception) {
                    // Backend transient error — keep polling.
                }
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    private fun stopPolling() {
        pollingJob?.cancel(); pollingJob = null
        firstHandshakeMs = 0L
        pollingStartedMs = 0L
    }

    private fun emit(next: TunnelUiState) {
        val prev = lastEmittedState
        _uiState.value = next
        lastEmittedState = next.state
        if (next.state == TunnelState.Connected && prev != TunnelState.Connected) {
            vibrateOnce()
        }
    }

    private fun vibrateOnce() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val vm = context.getSystemService(VibratorManager::class.java)
                vm?.defaultVibrator?.vibrate(VibrationEffect.createOneShot(80, VibrationEffect.DEFAULT_AMPLITUDE))
            } else {
                @Suppress("DEPRECATION")
                val vibrator = context.getSystemService(Vibrator::class.java)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    vibrator?.vibrate(VibrationEffect.createOneShot(80, VibrationEffect.DEFAULT_AMPLITUDE))
                } else {
                    @Suppress("DEPRECATION")
                    vibrator?.vibrate(80)
                }
            }
        } catch (_: Throwable) {
            // No vibrator / permission denied — silently ignore.
        }
    }

    companion object {
        private const val TUNNEL_NAME = "wgkeybot"
        private const val POLL_INTERVAL_MS = 2_000L
        private const val HANDSHAKE_DISPLAY_SECONDS = 5L
        // WireGuard REJECT_AFTER_TIME — peer is considered unreachable past this.
        private const val HANDSHAKE_STALE_SECONDS = 180L
        // Grace period for the first handshake after polling starts.
        private const val INITIAL_HANDSHAKE_TIMEOUT_MS = 30_000L
    }
}
