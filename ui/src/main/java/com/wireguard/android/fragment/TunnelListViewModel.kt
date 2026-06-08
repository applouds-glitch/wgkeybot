package com.wireguard.android.fragment

import androidx.lifecycle.ViewModel
import com.wireguard.android.Application
import kotlinx.coroutines.flow.StateFlow

class TunnelListViewModel : ViewModel() {

    /** Single source of truth lives in the Application-scope tracker. */
    val uiState: StateFlow<TunnelUiState>
        get() = Application.getTunnelStateTracker().uiState

    @Volatile var isConnecting = false
    @Volatile var cancelledByUser = false

    /** Auto-refresh is due but the tunnel isn't connected yet; fetch once we reach Connected. */
    @Volatile var pendingAutoRefresh = false

    /** A config refresh (manual or auto) is in flight — prevents overlapping fetches. */
    @Volatile var refreshInProgress = false

    // ── External notifications from Fragment ──────────────────────────────────

    fun notifyConnecting() {
        isConnecting = true
        Application.getTunnelStateTracker().signalUserConnect()
    }

    /** No-op: tracker picks up tunnel.state == UP on its own. Kept for source compatibility. */
    fun notifyTunnelUp() {
        isConnecting = false
    }

    /** No-op: tracker auto-polls while tunnel is UP. Kept for source compatibility. */
    fun ensurePollingActive() {
        isConnecting = false
    }

    fun notifyTunnelDown() {
        isConnecting = false
        Application.getTunnelStateTracker().signalUserDisconnect()
    }

    fun setConfigLoadedAt(ts: Long) = Application.getTunnelStateTracker().setConfigLoadedAt(ts)

    fun currentConfigLoadedAt(): Long = Application.getTunnelStateTracker().currentConfigLoadedAt()
}
