/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.model

/**
 * The background handshake watchdog's verdict on a single poll: is this tunnel
 * sitting on a dead route? Kept free of the backend, the clock and Android, so
 * the rules that end a user's session are pinned by plain JVM tests.
 */
internal object HandshakeWatchdog {
    // Handshake age beyond which an in-use connection is considered broken.
    const val STALE_MS = 180_000L

    // Grace period for a tunnel that has never completed a single handshake.
    const val NEVER_CONNECTED_MS = 150_000L

    /**
     * Whether this poll counts as dead. [prevTx] is the previous poll's tx, or a
     * negative value on the first poll, which has nothing to compare against.
     *
     * No physical network at all is never a dead route. Nothing can handshake
     * then, while WireGuard keeps sending initiations into the local proxy every
     * five seconds — so tx grows and the stale rule below used to read the
     * outage as a dead route and tear the session down after 1.5 to 4 minutes
     * without a network (a lift, the metro), leaving the VPN off once the
     * network came back. The native workers are parked for exactly this
     * (wgSetNetwork(null)), so waiting costs nothing. Returning false also
     * resets the caller's streak: a network that comes back gets the full
     * two-poll budget before a verdict, not whatever was left before it went.
     */
    fun isDeadPoll(
        now: Long,
        upSince: Long,
        latestHandshake: Long,
        tx: Long,
        prevTx: Long,
        hasPhysicalNetwork: Boolean,
    ): Boolean = when {
        !hasPhysicalNetwork -> false
        // Never completed a single handshake since coming up.
        latestHandshake == 0L -> now - upSince > NEVER_CONNECTED_MS
        // Handshake went stale while the app is still pushing traffic into
        // the tunnel (tx growing) — packets are going into a dead route.
        now - latestHandshake > STALE_MS -> prevTx >= 0L && tx > prevTx
        else -> false
    }
}
