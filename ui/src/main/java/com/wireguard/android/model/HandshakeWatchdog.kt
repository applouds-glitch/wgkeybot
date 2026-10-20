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
 *
 * Neither rebuild is made while the proxy says no relay answers over the
 * network (wgTurnPathSilentSeconds): a verdict then is [Step.HOLD]. The dark
 * spells of 18.10 and 08.10 were the phone's network carrying nothing for two
 * to seven minutes while Android called it up; a rebuild in one restarted the
 * proxy, which forgot the dark and sent every worker dialing into it again,
 * and the second dropped the cached credential for a VK request that could
 * not get through — and, once the network was back, cost a fetch the cache
 * would have spared, a captcha's chance included. The scouts dial the dark
 * meanwhile (dark_scout.go), and whatever relay answers them ends it. The
 * tunnel still goes down: [SILENT_HOLD_MS] after the verdict held, checked on
 * every poll while the relays stay silent — not on the next verdict, which
 * needs tx to grow, and an idle phone sends nothing once WireGuard gives up
 * its initiations: the hold would never have run out (Codex review, 19.10).
 * With the screen on that is about the ~9 minutes the steps it stands for
 * would take; with it off the polls are minutes apart, and it comes later.
 * Only a handshake since the hold began, or the network gone, ends it early.
 * Should the relays be dead rather than the network, no new credential —
 * another relay list — is tried while the silence lasts; nothing tells the two
 * apart from here, and the cache is what is kept. A verdict with the relays
 * answering again takes the step that was next.
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

        /** A verdict while no relay answers over the network: wait, rebuild nothing. */
        HOLD,

        /** Give up: take the tunnel down. */
        TEAR_DOWN,
    }

    // Handshakes older than this do not count: the session's start, then each rebuild.
    private var since = startedAt
    private var graceMs = HandshakeWatchdog.NEVER_CONNECTED_MS
    private var prevTx = -1L
    private var deadPolls = 0

    // When the verdict over a silent path was held; 0 while none is.
    private var heldSince = 0L

    /** Rebuilds since the last handshake; 0 while the session is healthy. */
    var rebuilds = 0
        private set

    /** [pathSilent]: the tunnel's own proxy hears no relay over the network (see above). */
    fun poll(now: Long, latestHandshake: Long, tx: Long, hasPhysicalNetwork: Boolean, pathSilent: Boolean = false): Step {
        val handshake = if (latestHandshake >= since) latestHandshake else 0L
        val recovered = handshake != 0L && rebuilds > 0
        if (recovered) rebuilds = 0
        if (heldSince != 0L && (!hasPhysicalNetwork || latestHandshake >= heldSince)) heldSince = 0L
        val dead = HandshakeWatchdog.isDeadPoll(now, since, handshake, tx, prevTx, hasPhysicalNetwork, graceMs)
        prevTx = tx
        if (heldSince != 0L && pathSilent) {
            deadPolls = 0
            return if (now - heldSince >= SILENT_HOLD_MS) Step.TEAR_DOWN else Step.NONE
        }
        if (!dead) {
            deadPolls = 0
            return if (recovered) Step.RECOVERED else Step.NONE
        }
        if (++deadPolls < DEAD_POLLS) return Step.NONE
        deadPolls = 0
        if (pathSilent) {
            heldSince = now
            return Step.HOLD
        }
        heldSince = 0L
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

        // How long a verdict over a silent path is held before the tunnel goes
        // down: the two rebuild steps it stands for, ~2.5 minutes each.
        const val SILENT_HOLD_MS = 5 * 60_000L
    }
}
