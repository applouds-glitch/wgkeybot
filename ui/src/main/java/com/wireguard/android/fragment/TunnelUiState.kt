package com.wireguard.android.fragment

enum class TunnelState {
    Disconnected,
    Connecting,
    Handshake,
    Connected,
}

data class TunnelUiState(
    val state: TunnelState = TunnelState.Disconnected,
    val uptimeSeconds: Long = 0L,
    val rxBytes: Long = 0L,
    val txBytes: Long = 0L,
    val configLoadedAt: Long = 0L,
)
