/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.model

/**
 * When the user is told that the tunnel's config is up on another device too,
 * and when that notice comes down again. The finding itself is native
 * (peer_conflict.go, TurnBackend.wgPeerConflictSeconds): WireGuard's server
 * answers a handshake at once and goes quiet within seconds, over and over —
 * one key serves one device, and each device's handshake takes the session
 * from the other. Seen on 2026-11-14 with a second phone on the same config:
 * nine minutes of it, the relays healthy, nothing on screen.
 *
 * Nothing in the app can win the session back; only the user can take the
 * other device off the config, so the notice is all there is to do. Once per
 * conflict, not once per poll, and gone when the conflict is, so it never
 * stands over a tunnel that works.
 */
internal class PeerConflictAlert {
    enum class Step { NONE, ALERT, CLEAR }

    /** Whether the notice is up now. */
    var alerted = false
        private set

    /** [conflictSeconds]: TurnBackend.wgPeerConflictSeconds, 0 while there is no conflict. */
    fun poll(conflictSeconds: Int): Step = when {
        conflictSeconds > 0 && !alerted -> {
            alerted = true
            Step.ALERT
        }
        conflictSeconds <= 0 && alerted -> {
            alerted = false
            Step.CLEAR
        }
        else -> Step.NONE
    }
}
