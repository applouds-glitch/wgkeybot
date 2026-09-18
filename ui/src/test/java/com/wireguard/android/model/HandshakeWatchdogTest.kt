/* SPDX-License-Identifier: Apache-2.0 */

package com.wireguard.android.model

import com.wireguard.android.model.HandshakeWatchdog.NEVER_CONNECTED_MS
import com.wireguard.android.model.HandshakeWatchdog.STALE_MS
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HandshakeWatchdogTest {
    private val upSince = 1_000_000L
    private val now = upSince + 10 * STALE_MS

    private fun poll(
        latestHandshake: Long,
        tx: Long = 2_000,
        prevTx: Long = 1_000,
        hasPhysicalNetwork: Boolean = true,
    ) = HandshakeWatchdog.isDeadPoll(now, upSince, latestHandshake, tx, prevTx, hasPhysicalNetwork)

    @Test
    fun `stale handshake with traffic still going out is a dead route`() {
        assertTrue(poll(latestHandshake = now - STALE_MS - 1))
    }

    @Test
    fun `no physical network is waiting, not a dead route`() {
        // Exactly the outage shape: stale handshake, and tx growing because
        // WireGuard keeps sending initiations into the local proxy.
        assertFalse(poll(latestHandshake = now - STALE_MS - 1, hasPhysicalNetwork = false))
    }

    @Test
    fun `no physical network holds the verdict for a tunnel that never connected`() {
        assertFalse(poll(latestHandshake = 0L, hasPhysicalNetwork = false))
    }

    @Test
    fun `stale handshake on an idle tunnel is not dead`() {
        assertFalse(poll(latestHandshake = now - STALE_MS - 1, tx = 1_000, prevTx = 1_000))
    }

    @Test
    fun `first poll has no traffic baseline to judge by`() {
        assertFalse(poll(latestHandshake = now - STALE_MS - 1, prevTx = -1L))
    }

    @Test
    fun `recent handshake is not dead however much goes out`() {
        assertFalse(poll(latestHandshake = now - STALE_MS))
    }

    @Test
    fun `never connected is dead only after its grace`() {
        val justUp = upSince + NEVER_CONNECTED_MS
        assertFalse(HandshakeWatchdog.isDeadPoll(justUp, upSince, 0L, 2_000, 1_000, true))
        assertTrue(HandshakeWatchdog.isDeadPoll(justUp + 1, upSince, 0L, 2_000, 1_000, true))
    }
}
