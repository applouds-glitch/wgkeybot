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

    // The same for a TURN transport the watchdog has just rebuilt: WireGuard
    // retries its initiation every 5s, so a working path handshakes within
    // seconds. With the second poll that confirms it, ~2.5 minutes a step.
    const val REBUILT_GRACE_MS = 90_000L

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
     *
     * [graceMs] is how long a tunnel that has not handshaken yet since [upSince]
     * is given.
     */
    fun isDeadPoll(
        now: Long,
        upSince: Long,
        latestHandshake: Long,
        tx: Long,
        prevTx: Long,
        hasPhysicalNetwork: Boolean,
        graceMs: Long = NEVER_CONNECTED_MS,
    ): Boolean = when {
        !hasPhysicalNetwork -> false
        // Never completed a single handshake since coming up.
        latestHandshake == 0L -> now - upSince > graceMs
        // Handshake went stale while the app is still pushing traffic into
        // the tunnel (tx growing) — packets are going into a dead route.
        now - latestHandshake > STALE_MS -> prevTx >= 0L && tx > prevTx
        else -> false
    }
}

/**
 * The background watchdog's course over one tunnel session: what each poll's
 * verdict leads to. Pure, like [HandshakeWatchdog], so the steps are pinned by
 * JVM tests.
 *
 * A dead verdict confirmed by [DEAD_POLLS] polls in a row used to take the
 * tunnel down straight away, about four minutes after the last handshake. The
 * native workers retry on their own all that time, so waiting longer adds
 * nothing by itself; what does is a different action. So the first two
 * verdicts rebuild the TURN transport instead — the second time on a new VK
 * identity — and only a third takes the tunnel down: ~9 minutes in all, close
 * to what WDTT-Plus spends before it stops a connection that its own restarts
 * could not bring back.
 *
 * After a rebuild the old handshake no longer counts: the new transport gets
 * [HandshakeWatchdog.REBUILT_GRACE_MS] to handshake, measured from the rebuild.
 * A handshake after a rebuild means it worked, and a later failure starts over
 * from the first step.
 */
internal class WatchdogCourse(startedAt: Long) {
    enum class Step {
        /** Nothing to do. */
        NONE,

        /** A handshake came through after a rebuild: the transport is back. */
        RECOVERED,

        /** Rebuild the TURN transport on the same credential. */
        REBUILD,

        /** Rebuild it on a new credential (one VK request). */
        REBUILD_NEW_CREDENTIALS,

        /** Give up: take the tunnel down. */
        TEAR_DOWN,
    }

    // Handshakes older than this do not count: the session's start, then each rebuild.
    private var since = startedAt
    private var graceMs = HandshakeWatchdog.NEVER_CONNECTED_MS
    private var prevTx = -1L
    private var deadPolls = 0

    /** Rebuilds since the last handshake; 0 while the session is healthy. */
    var rebuilds = 0
        private set

    fun poll(now: Long, latestHandshake: Long, tx: Long, hasPhysicalNetwork: Boolean): Step {
        val handshake = if (latestHandshake >= since) latestHandshake else 0L
        val recovered = handshake != 0L && rebuilds > 0
        if (recovered) rebuilds = 0
        val dead = HandshakeWatchdog.isDeadPoll(now, since, handshake, tx, prevTx, hasPhysicalNetwork, graceMs)
        prevTx = tx
        if (!dead) {
            deadPolls = 0
            return if (recovered) Step.RECOVERED else Step.NONE
        }
        if (++deadPolls < DEAD_POLLS) return Step.NONE
        deadPolls = 0
        return when {
            rebuilds >= REBUILDS -> Step.TEAR_DOWN
            rebuilds++ == 0 -> Step.REBUILD
            else -> Step.REBUILD_NEW_CREDENTIALS
        }
    }

    /** The transport was rebuilt at [at]: judge the new one from there. */
    fun rebuilt(at: Long) {
        since = at
        graceMs = HandshakeWatchdog.REBUILT_GRACE_MS
        prevTx = -1L
        deadPolls = 0
    }

    companion object {
        // Consecutive dead polls that make a verdict (debounce).
        const val DEAD_POLLS = 2

        // Rebuilds before the tunnel is taken down; all but the first on a new credential.
        const val REBUILDS = 2
    }
}
