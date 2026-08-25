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

/**
 * Why the session died, when the cause is known and worth telling the user apart
 * from "the handshake never arrived".
 *
 * The native TURN layer and [com.wireguard.android.turn.TurnProxyManager] both
 * reach terminal conclusions the UI used to throw away: the tunnel was taken down
 * and the screen fell back to plain Disconnected, so the only trace left was a
 * system notification the user had usually already swiped away. The reason now
 * rides on [TunnelUiState] and holds the screen in [TunnelState.Failed] until the
 * next tap.
 *
 * A null failure is the ordinary case — the handshake watchdog gave up, and
 * "server unreachable, check your network" is all anyone can say.
 */
enum class TunnelFailure {
    /** The VK call has ended or the link is wrong: another attempt cannot fix it. */
    CallUnavailable,

    /** The call refuses anonymous joins (CALL_REQUIRES_AUTH). */
    CallRequiresAuth,

    /** The solve ladder lost its budget of attempts — the captcha gate is shut. */
    CaptchaUnsolved,

    /** Credentials could not be obtained, for a reason we cannot narrow further. */
    Credentials,

    /** The proxy could not be brought back, typically after a network change. */
    ProxyRestart;

    companion object {
        /**
         * Classifies a reason string coming up from Go (`reportWorkerGaveUp`) or
         * from the restart loop. The strings are error texts, not a protocol, so
         * this matches loosely and returns null when nothing fits — the caller
         * picks the default that suits its own path.
         */
        fun fromTurnReason(reason: String): TunnelFailure? {
            val r = reason.uppercase()
            return when {
                r.contains("CALL_REQUIRES_AUTH") -> CallRequiresAuth
                r.contains("CALL_UNAVAILABLE") -> CallUnavailable
                r.contains("CAPTCHA") -> CaptchaUnsolved
                else -> null
            }
        }
    }
}

data class TunnelUiState(
    val state: TunnelState = TunnelState.Disconnected,
    val uptimeSeconds: Long = 0L,
    val rxBytes: Long = 0L,
    val txBytes: Long = 0L,
    val configLoadedAt: Long = 0L,
    /** Only meaningful while [state] is [TunnelState.Failed]. */
    val failure: TunnelFailure? = null,
)
