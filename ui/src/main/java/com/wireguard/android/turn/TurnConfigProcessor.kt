/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import com.wireguard.config.Config
import com.wireguard.config.Peer
import java.util.ArrayList

/**
 * Utility for processing WireGuard configurations to inject, extract, and modify TURN settings.
 */
object TurnConfigProcessor {

    /**
     * Injects TURN settings into the first peer of the configuration as special comments.
     */
    fun injectTurnSettings(config: Config, turnSettings: TurnSettings?): Config {
        if (turnSettings == null) return config
        val peers = config.peers
        if (peers.isEmpty()) return config

        val newPeers = ArrayList<Peer>()
        for (i in peers.indices) {
            val peer = peers[i]
            if (i == 0) {
                val builder = Peer.Builder()
                builder.addAllowedIps(peer.allowedIps)
                builder.setPublicKey(peer.publicKey)
                peer.endpoint.ifPresent { builder.setEndpoint(it) }
                peer.persistentKeepalive.ifPresent { builder.setPersistentKeepalive(it) }
                peer.preSharedKey.ifPresent { builder.setPreSharedKey(it) }

                // Add existing extra lines (excluding our own to avoid duplicates)
                val filteredLines = peer.extraLines.filter { !it.startsWith("#@wgt:") && !it.contains("TURN extensions") }
                builder.addExtraLines(filteredLines)

                // Add TURN settings as comments
                builder.addExtraLines(turnSettings.toComments())
                newPeers.add(builder.build())
            } else {
                newPeers.add(peer)
            }
        }

        return Config.Builder()
            .setInterface(config.`interface`)
            .addPeers(newPeers)
            .build()
    }

    /**
     * Extracts TURN settings from the configuration comments.
     */
    fun extractTurnSettings(config: Config): TurnSettings? {
        for (peer in config.peers) {
            val settings = TurnSettings.fromComments(peer.extraLines)
            if (settings != null) return settings
        }
        return null
    }

    /**
     * Modifies the configuration for active TURN usage (replaces Endpoint with local loopback and sets the MTU).
     * The native TURN grid drives WireGuard keepalives too, so an independent
     * PersistentKeepalive timer must stay disabled to avoid a second radio wake window.
     */
    fun modifyConfigForActiveTurn(config: Config, turnSettings: TurnSettings): Config {
        val iface = config.`interface`
        val ifaceBuilder = com.wireguard.config.Interface.Builder()
        ifaceBuilder.addAddresses(iface.addresses)
        ifaceBuilder.addDnsServers(iface.dnsServers)
        ifaceBuilder.addDnsSearchDomains(iface.dnsSearchDomains)
        ifaceBuilder.setKeyPair(iface.keyPair)
        ifaceBuilder.excludeApplications(iface.excludedApplications)
        ifaceBuilder.includeApplications(iface.includedApplications)

        try {
            ifaceBuilder.setListenPort(iface.listenPort.orElse(0))
            // MTU comes from the config; 1200 only when the config omits it.
            ifaceBuilder.setMtu(iface.mtu.orElse(1200))
        } catch (e: Exception) {
            // Should not happen with valid port/mtu
        }

        val builder = Config.Builder()
        try {
            builder.setInterface(ifaceBuilder.build())
        } catch (e: Exception) {
            // Fallback to original interface if building fails
            builder.setInterface(iface)
        }

        val localPort = turnSettings.localPort

        for (peer in config.peers) {
            val peerBuilder = Peer.Builder()
            peerBuilder.addAllowedIps(peer.allowedIps)
            peerBuilder.setPublicKey(peer.publicKey)
            peer.preSharedKey.ifPresent { peerBuilder.setPreSharedKey(it) }

            // Deliberately omit PersistentKeepalive for every active TURN mode,
            // including peerType="wireguard" (raw WireGuard over TURN/WRAP).
            // Configurations without TURN never pass through this method and
            // retain the user's original setting.

            // Replace endpoint with 127.0.0.1:localPort
            peerBuilder.parseEndpoint("127.0.0.1:$localPort")
            builder.addPeer(peerBuilder.build())
        }
        return builder.build()
    }
}
