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
     * Modifies the configuration for active TURN usage (replaces Endpoint with local loopback).
     */
    fun modifyConfigForActiveTurn(config: Config, localPort: Int): Config {
        val builder = Config.Builder()
        builder.setInterface(config.`interface`)
        for (peer in config.peers) {
            val peerBuilder = Peer.Builder()
            peerBuilder.addAllowedIps(peer.allowedIps)
            peerBuilder.setPublicKey(peer.publicKey)
            peer.preSharedKey.ifPresent { peerBuilder.setPreSharedKey(it) }
            peer.persistentKeepalive.ifPresent { peerBuilder.setPersistentKeepalive(it.toInt()) }
            // Replace endpoint with 127.0.0.1:localPort
            peerBuilder.parseEndpoint("127.0.0.1:$localPort")
            builder.addPeer(peerBuilder.build())
        }
        return builder.build()
    }
}
