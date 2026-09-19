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
 */
internal object PhysicalNetworkChoice {
    enum class Transport { WIFI, CELLULAR, OTHER }

    data class Candidate<T>(val id: T, val transport: Transport)

    /** What Android says is the best physical network; [network] is null when it has none. */
    data class SystemPick<T>(val network: T?)

    /**
     * The network to bind to, or null when there is none. [system] is null while
     * the platform has not told us its pick; once it has, that is the answer —
     * including "none", whatever [candidates] may still hold.
     */
    fun <T> pick(system: SystemPick<T>?, candidates: List<Candidate<T>>): T? {
        if (system != null) return system.network
        return (candidates.firstOrNull { it.transport == Transport.WIFI }
            ?: candidates.firstOrNull { it.transport == Transport.CELLULAR }
            ?: candidates.firstOrNull())?.id
    }
}
