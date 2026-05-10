package com.wireguard.android.fragment

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.wireguard.android.Application
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.model.ObservableTunnel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

private const val TUNNEL_NAME = "wgkeybot"
private const val HANDSHAKE_DISPLAY_SECONDS = 5L

class TunnelListViewModel : ViewModel() {

    private val _uiState = MutableStateFlow(TunnelUiState())
    val uiState: StateFlow<TunnelUiState> = _uiState.asStateFlow()

    @Volatile var isConnecting = false
    @Volatile var cancelledByUser = false

    private var statsJob: Job? = null
    private var uptimeJob: Job? = null
    private var connectedSinceMs = 0L
    private var firstHandshakeMs = 0L

    // ── External notifications from Fragment ──────────────────────────────────

    fun notifyConnecting() {
        isConnecting = true
        _uiState.value = _uiState.value.copy(state = TunnelState.Connecting)
    }

    fun notifyTunnelUp() {
        isConnecting = false
        connectedSinceMs = System.currentTimeMillis()
        firstHandshakeMs = 0L
        startStatsPolling()
        startUptimeTicker()
    }

    /** Start polling only if not already running (safe to call on Fragment resume). */
    fun ensurePollingActive() {
        if (statsJob?.isActive == true) return
        notifyTunnelUp()
    }

    fun notifyTunnelDown() {
        isConnecting = false
        stopPolling()
        _uiState.value = TunnelUiState(configLoadedAt = _uiState.value.configLoadedAt)
    }

    fun setConfigLoadedAt(ts: Long) {
        _uiState.value = _uiState.value.copy(configLoadedAt = ts)
    }

    fun currentConfigLoadedAt(): Long = _uiState.value.configLoadedAt

    // ── Polling ───────────────────────────────────────────────────────────────

    private fun startStatsPolling() {
        statsJob?.cancel()
        statsJob = viewModelScope.launch(Dispatchers.IO) {
            while (isActive) {
                try {
                    val tunnel = Application.getTunnelManager().getTunnels()
                        .firstOrNull { it.name == TUNNEL_NAME }
                    if (tunnel == null) {
                        notifyTunnelDown()
                        break
                    }

                    val stats = tunnel.getStatisticsAsync()
                    val lastHandshakeMs = stats.peers()
                        .mapNotNull { stats.peer(it)?.latestHandshakeEpochMillis }
                        .maxOrNull() ?: 0L
                    val rx = stats.totalRx()
                    val tx = stats.totalTx()

                    val newState = when {
                        lastHandshakeMs == 0L -> TunnelState.Connecting
                        firstHandshakeMs == 0L || (System.currentTimeMillis() - firstHandshakeMs) / 1000 < HANDSHAKE_DISPLAY_SECONDS -> {
                            if (firstHandshakeMs == 0L) firstHandshakeMs = System.currentTimeMillis()
                            TunnelState.Handshake
                        }
                        else -> TunnelState.Connected
                    }

                    _uiState.value = _uiState.value.copy(state = newState, rxBytes = rx, txBytes = tx)
                } catch (_: Exception) { }
                delay(2_000L)
            }
        }
    }

    private fun startUptimeTicker() {
        uptimeJob?.cancel()
        uptimeJob = viewModelScope.launch {
            while (isActive) {
                val seconds = (System.currentTimeMillis() - connectedSinceMs) / 1000
                _uiState.value = _uiState.value.copy(uptimeSeconds = seconds)
                delay(1_000L)
            }
        }
    }

    private fun stopPolling() {
        statsJob?.cancel(); statsJob = null
        uptimeJob?.cancel(); uptimeJob = null
        connectedSinceMs = 0L
        firstHandshakeMs = 0L
    }

    override fun onCleared() {
        super.onCleared()
        stopPolling()
    }
}
