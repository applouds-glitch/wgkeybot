/*
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.fragment

import org.junit.Assert.assertEquals
import org.junit.Test

class TunnelStatePolicyTest {
    private val now = 10_000_000L
    private val started = now - 600_000L          // polling for ten minutes
    private val freshHandshake = now - 20_000L    // well inside REJECT_AFTER_TIME
    private val firstSeen = now - 500_000L

    private fun derive(
        lastHandshakeMs: Long = freshHandshake,
        firstHandshakeSeenMs: Long = firstSeen,
        hasNetwork: Boolean = true,
        readyStreams: Int = 10,
        pollingStartedMs: Long = started,
    ) = TunnelStatePolicy.derive(now, pollingStartedMs, lastHandshakeMs, firstHandshakeSeenMs, hasNetwork, readyStreams)

    @Test
    fun `a healthy session is connected`() {
        assertEquals(TunnelState.Connected, derive())
        // One stream is enough to carry the tunnel.
        assertEquals(TunnelState.Connected, derive(readyStreams = 1))
    }

    /**
     * The point of it: the handshake is still fresh for minutes after the path
     * died, and the screen used to say "Connected" all that time.
     */
    @Test
    fun `no network is said at once and is not called reconnecting`() {
        assertEquals(TunnelState.WaitingForNetwork, derive(hasNetwork = false))
        // Whatever the streams say: they cannot come back without a network.
        assertEquals(TunnelState.WaitingForNetwork, derive(hasNetwork = false, readyStreams = 0))
        // And whatever the handshake says.
        assertEquals(TunnelState.WaitingForNetwork, derive(hasNetwork = false, lastHandshakeMs = now - 400_000L))
    }

    @Test
    fun `no stream up is reconnecting at once with the handshake still fresh`() {
        assertEquals(TunnelState.Reconnecting, derive(readyStreams = 0))
    }

    @Test
    fun `a tunnel that does not run over TURN is judged by its handshake alone`() {
        assertEquals(TunnelState.Connected, derive(readyStreams = -1))
        assertEquals(TunnelState.Reconnecting, derive(readyStreams = -1, lastHandshakeMs = now - 181_000L))
        assertEquals(TunnelState.Connected, derive(readyStreams = -1, lastHandshakeMs = now - 179_000L))
    }

    @Test
    fun `a stale handshake is reconnecting even with every stream up`() {
        assertEquals(TunnelState.Reconnecting, derive(lastHandshakeMs = now - 181_000L))
    }

    /** Before the first handshake the tunnel is connecting, and the connect's own deadline rules. */
    @Test
    fun `the first connect is not read as a lost network or a reconnect`() {
        val justStarted = now - 5_000L
        assertEquals(TunnelState.Connecting, derive(lastHandshakeMs = 0, firstHandshakeSeenMs = 0, pollingStartedMs = justStarted, readyStreams = 0))
        assertEquals(TunnelState.Connecting, derive(lastHandshakeMs = 0, firstHandshakeSeenMs = 0, pollingStartedMs = justStarted, hasNetwork = false))
        assertEquals(TunnelState.Failed, derive(lastHandshakeMs = 0, firstHandshakeSeenMs = 0, pollingStartedMs = now - 31_000L))
    }

    @Test
    fun `the first handshake is shown for a few seconds before connected`() {
        assertEquals(TunnelState.Handshake, derive(firstHandshakeSeenMs = 0))
        assertEquals(TunnelState.Handshake, derive(firstHandshakeSeenMs = now - 4_000L))
        assertEquals(TunnelState.Connected, derive(firstHandshakeSeenMs = now - 5_000L))
    }
}
