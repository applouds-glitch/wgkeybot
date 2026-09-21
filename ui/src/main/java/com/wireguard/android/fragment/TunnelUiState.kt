package com.wireguard.android.fragment

enum class TunnelState {
    Disconnected,
    Connecting,
    Handshake,
    Connected,
    // Tunnel is up but its transport is not: no TURN stream is carrying it, or
    // no fresh handshake (peer unreachable >180s).
    Reconnecting,
    // Tunnel is up and the phone has no physical network at all: nothing to
    // reconnect over until one returns.
    WaitingForNetwork,
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
    Credentials;

    companion object {
        /**
         * Classifies a reason string coming up from Go (`reportWorkerGaveUp`).
         * The strings are error texts, not a protocol, so
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
    /** Monotonic session origin; views compute elapsed time only while visible. */
    val sessionStartedAtElapsedMs: Long = 0L,
    val rxBytes: Long = 0L,
    val txBytes: Long = 0L,
    val configLoadedAt: Long = 0L,
    /** Only meaningful while [state] is [TunnelState.Failed]. */
    val failure: TunnelFailure? = null,
)

/**
 * What the screen says about a tunnel that is up, from what is known at one
 * poll. Pure, so the order of the rules can be pinned by a test.
 *
 * WireGuard's handshake is the slow witness: it goes stale three minutes after
 * the path died. Until 2026-09-21 it was the only one, so a network drop read
 * "Connected" all the way through — the streams died, the workers redialed, the
 * streams came back, and the screen never said a word; and when they did not
 * come back, it said so minutes late. Two faster facts go first:
 *
 *  - there is no physical network: nothing can reconnect, and saying
 *    "reconnecting" would promise what cannot happen — [TunnelState.WaitingForNetwork];
 *  - there is one, the tunnel runs over TURN, and no stream is ready
 *    ([readyStreams] == 0): [TunnelState.Reconnecting], at once.
 *
 * Both apply only to a session that has had its first handshake: before it the
 * tunnel is still connecting and says so, and the connect's own deadline rules.
 * [readyStreams] is -1 for a tunnel that does not run over TURN (or whose proxy
 * is not running), which leaves the handshake as the only witness, as before.
 */
object TunnelStatePolicy {
    const val HANDSHAKE_DISPLAY_SECONDS = 5L
    // WireGuard REJECT_AFTER_TIME — peer is considered unreachable past this.
    const val HANDSHAKE_STALE_SECONDS = 180L
    // Grace period for the first handshake after polling starts.
    const val INITIAL_HANDSHAKE_TIMEOUT_MS = 30_000L

    fun derive(
        nowMs: Long,
        pollingStartedMs: Long,
        lastHandshakeMs: Long,
        firstHandshakeSeenMs: Long,
        hasNetwork: Boolean,
        readyStreams: Int,
    ): TunnelState = when {
        lastHandshakeMs == 0L ->
            if (nowMs - pollingStartedMs > INITIAL_HANDSHAKE_TIMEOUT_MS) TunnelState.Failed
            else TunnelState.Connecting
        !hasNetwork -> TunnelState.WaitingForNetwork
        readyStreams == 0 -> TunnelState.Reconnecting
        (nowMs - lastHandshakeMs) / 1000 > HANDSHAKE_STALE_SECONDS -> TunnelState.Reconnecting
        firstHandshakeSeenMs == 0L ||
            (nowMs - firstHandshakeSeenMs) / 1000 < HANDSHAKE_DISPLAY_SECONDS -> TunnelState.Handshake
        else -> TunnelState.Connected
    }
}
