/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

/**
 * Which physical network the TURN sockets bind to. Kept free of Android, so the
 * rule that moves a user's sessions from one network to another is pinned by
 * plain JVM tests.
 *
 * The rule is to go where Android goes, and to hold no opinion of our own about
 * which network is good.
 *
 * Between 2026-07-20 and 2026-09-19 there was such an opinion, built on
 * NET_CAPABILITY_VALIDATED, in two places: the native network gate and this
 * choice ("prefer a validated network"). For the networks this client exists
 * for the signal is simply wrong — behind a mobile whitelist Google's
 * connectivity check fails while VK's relays answer — and both uses cost field
 * sessions: the gate throttled recovery to one dial a minute, and the choice
 * walked the tunnel off a cellular network the moment the whitelist was switched
 * on. v1.6.0, which people remember as holding a connection better, knew nothing
 * about validation; neither does the other client of these relays, whose
 * transport is not bound to a network at all and so rides the system default.
 *
 * Android's own ranking does use validation, but together with everything we
 * cannot see: that the user tapped "use this network anyway", that a Wi-Fi is a
 * captive portal, the avoid-bad-Wi-Fi setting. It is also the network every
 * other app on the phone is using — when it is the wrong one the phone has no
 * internet for anything, and the user's fix (turn that Wi-Fi off) fixes us too.
 *
 * Where the platform cannot tell us its pick (before API 31, or until its first
 * report) the choice is v1.6.0's: Wi-Fi, then cellular, then whatever there is.
 *
 * Android's pick reaches us through a callback, and a callback can be stale. In
 * the field logs of 2026-10-09/10 (Pixel 9, Android 17) it said "no network"
 * five times, mostly within milliseconds of the app coming back to the screen
 * with the tunnel off, while the phone was on cellular: unbound sockets reached
 * DNS and VK, and the app's own HTTP went out from the operator's address. It
 * stayed "no network" for up to 22 minutes, until some other network event came
 * along, and every connect in between failed with the workers parked. So "no
 * network" from the callback is checked against what Android says when asked
 * directly, which cannot be stale: a physical network there is the answer.
 * Before the tunnel is up that is the default network, the one every app uses.
 * Once it is up, the app rides its own tunnel and the default is the VPN, so the
 * network in use stands for as long as Android still knows it.
 *
 * Not at once, though. "Cannot be stale" held for the minutes-long "none" it was
 * written for, and not for the "none" of a network going away: for a second or
 * two after the callback's onLost, the direct question still names the lost
 * network. Field log 2026-10-12 (Xiaomi, HyperOS, Android 16, cellular that
 * reconnects every 10-15s): eight stand-ins in half an hour, every one of them a
 * network already gone — no link properties, no DNS servers, every bind refused
 * ("bindSocket exception") — and every time a new network came 1-3s later. The
 * workers were never parked and dialed into the dead network meanwhile. Across
 * that log and the one before it, the new network followed "none" within 2.8s at
 * most, so a "none" is believed for [STALE_NONE_AFTER_MS] first; the re-asking
 * that comes after it (every 10s) is the first time the stand-in can apply.
 */
internal object PhysicalNetworkChoice {
    enum class Transport { WIFI, CELLULAR, OTHER }

    data class Candidate<T>(val id: T, val transport: Transport)

    /** What Android says is the best physical network; [network] is null when it has none. */
    data class SystemPick<T>(val network: T?)

    /**
     * The network to bind to, or null when there is none. [system] is null while
     * the platform has not told us its pick; once it has, that is the answer.
     * Its "none" is not taken from [candidates], which are stale by then, but
     * from [systemDefault]: the physical network the platform has for this app
     * when asked directly, if any — once the "none" has lasted [noneForMs] of at
     * least [STALE_NONE_AFTER_MS].
     */
    fun <T> pick(
        system: SystemPick<T>?,
        candidates: List<Candidate<T>>,
        systemDefault: T? = null,
        noneForMs: Long = Long.MAX_VALUE,
    ): T? {
        system?.network?.let { return it }
        if (system == null) return byTransport(candidates).firstOrNull() ?: systemDefault
        return systemDefault.takeIf { noneForMs >= STALE_NONE_AFTER_MS }
    }

    /**
     * How long Android's "no network" is believed before [pick] checks it against
     * the default network: longer than a lost network takes to be replaced
     * (2.8s at most in the field), far shorter than the stale "none" (minutes).
     */
    const val STALE_NONE_AFTER_MS = 5_000L

    /**
     * The networks to try binding something else of ours to, best first: the one
     * the TURN sockets are on, then the rest by transport.
     *
     * For the captcha WebView, which binds the whole process to a physical
     * network to get out from under the tunnel. It used to take the first non-VPN
     * network the platform listed — in no particular order, background networks
     * included — so with Wi-Fi and cellular both up the captcha could go out over
     * a different network than the relays are reached over, or over one the app
     * is not allowed to bind to. A solve ladder that fails arms the captcha
     * lockout, and enough of those end the session (onTurnFatal).
     *
     * A list and not one answer because binding can be refused; [inUse] leads
     * even when we have not seen it among [candidates] ourselves.
     */
    fun <T> bindOrder(inUse: T?, candidates: List<Candidate<T>>): List<T> =
        (listOfNotNull(inUse) + byTransport(candidates)).distinct()

    private fun <T> byTransport(candidates: List<Candidate<T>>): List<T> =
        (candidates.filter { it.transport == Transport.WIFI } +
            candidates.filter { it.transport == Transport.CELLULAR } +
            candidates.filter { it.transport == Transport.OTHER }).map { it.id }
}
