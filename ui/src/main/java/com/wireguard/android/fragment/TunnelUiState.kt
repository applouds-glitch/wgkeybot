package com.wireguard.android.fragment

enum class TunnelState {
    Disconnected,
    Connecting,
    Handshake,
    Connected,
    // Tunnel is up but no fresh handshake (peer unreachable >180s).
    Reconnecting,
    // Initial connection didn't produce a handshake within the grace period.
    Failed,
}

data class TunnelUiState(
    val state: TunnelState = TunnelState.Disconnected,
    val uptimeSeconds: Long = 0L,
    val rxBytes: Long = 0L,
    val txBytes: Long = 0L,
    val configLoadedAt: Long = 0L,
)
