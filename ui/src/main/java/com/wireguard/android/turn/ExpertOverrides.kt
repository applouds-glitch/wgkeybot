/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import com.wireguard.config.InetAddresses
import com.wireguard.config.ParseException
import java.net.InetAddress

/**
 * What expert mode changes in the bot's configuration for the tunnel that is
 * about to come up: the interface MTU and the resolvers inside the tunnel. A
 * null field means "leave the config's value alone".
 *
 * Pure data, applied by [TurnConfigProcessor.modifyConfigForActiveTurn] to the
 * config handed to WireGuard and never written into the stored one: the bot
 * reissues that config, and a value edited into the file would be dropped at
 * its next refresh. [ExpertSettings] is where the values live between starts.
 */
data class ExpertOverrides(
    val mtu: Int? = null,
    val dns: List<InetAddress>? = null,
) {
    val isEmpty: Boolean get() = mtu == null && dns == null

    companion object {
        val NONE = ExpertOverrides()

        /**
         * The MTU the screen accepts. The floor keeps WireGuard's own minimum
         * (IPv6 needs 1280, but the bot's tunnels are IPv4) with room to spare
         * for the odd carrier path, the ceiling is Ethernet: over TURN every
         * inner packet gains ~110 B on the wire (see [TurnConfigProcessor]), so
         * anything above it only fragments.
         */
        const val MTU_MIN = 1000
        const val MTU_MAX = 1500

        fun isValidMtu(mtu: Int): Boolean = mtu in MTU_MIN..MTU_MAX

        /**
         * Parses a comma separated list of IP addresses. Empty text is an empty
         * list; null when any entry is not a numeric address — names are refused,
         * a resolver cannot itself be a name to resolve.
         */
        fun parseDns(text: String): List<InetAddress>? {
            val parts = text.split(',').map { it.trim() }.filter { it.isNotEmpty() }
            return try {
                parts.map { InetAddresses.parse(it) }
            } catch (_: ParseException) {
                null
            }
        }

        fun formatDns(servers: List<InetAddress>): String = servers.joinToString(", ") { it.hostAddress ?: it.toString() }
    }
}
