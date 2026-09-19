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
 * Android's validation is a reason to go to a network, never a reason to leave
 * one. A validated network wins, Wi-Fi before cellular — that is the handover
 * to a Wi-Fi that really has internet, and the way off a Wi-Fi whose uplink
 * died. But when nothing is validated, the network we are on stays: behind a
 * mobile whitelist Google's connectivity check fails while VK's relays answer,
 * so a cellular network that has just lost VALIDATED — the whitelist was turned
 * on mid-session — is very likely still carrying the tunnel, and the unvalidated
 * Wi-Fi the transport order would pick instead is very likely not.
 *
 * The old rule fell back to plain "Wi-Fi, then cellular" the moment nothing was
 * validated, and every such move recycles all sessions (network_switch.go) —
 * here onto a network that has shown no sign of a path to the relays.
 *
 * Staying is bounded by the system, and that is the limit of what this rule can
 * do. The app holds no CHANGE_NETWORK_STATE, so it is only ever shown foreground
 * networks; the system's own ranking (NetworkRanker) prefers Wi-Fi once nothing
 * is validated, and the cellular network it leaves is reported lost to us when
 * its linger (30s) runs out. Holding on to cellular past that would take a
 * network request of our own, which is a mechanism for another build.
 */
internal object PhysicalNetworkChoice {
    enum class Transport { WIFI, CELLULAR, OTHER }

    data class Candidate<T>(val id: T, val transport: Transport, val validated: Boolean)

    /** The network to bind to, or null when there is none. [current] is the one in use now. */
    fun <T> pick(candidates: List<Candidate<T>>, current: T?): T? {
        val validated = candidates.filter { it.validated }
        if (validated.isNotEmpty()) return byTransport(validated)
        candidates.firstOrNull { it.id == current }?.let { return it.id }
        return byTransport(candidates)
    }

    /** True when [pick] kept [current] against the transport order, for the log. */
    fun <T> keptAgainstTransportOrder(candidates: List<Candidate<T>>, current: T?): Boolean =
        candidates.none { it.validated } &&
            candidates.any { it.id == current } &&
            byTransport(candidates) != current

    private fun <T> byTransport(candidates: List<Candidate<T>>): T? =
        (candidates.firstOrNull { it.transport == Transport.WIFI }
            ?: candidates.firstOrNull { it.transport == Transport.CELLULAR }
            ?: candidates.firstOrNull())?.id
}
