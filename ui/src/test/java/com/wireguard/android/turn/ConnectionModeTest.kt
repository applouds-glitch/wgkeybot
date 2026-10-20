/* SPDX-License-Identifier: Apache-2.0 */

package com.wireguard.android.turn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConnectionModeTest {
    @Test
    fun `an SRTP config has no reserve mode`() {
        // The reserve mode is proxy_v2, and an SRTP server speaks nothing else.
        assertFalse(ConnectionMode.isOffered("srtp"))
    }

    @Test
    fun `every other peer type keeps the choice`() {
        for (peerType in listOf("proxy_v2", "proxy_v1", "wireguard")) {
            assertTrue(peerType, ConnectionMode.isOffered(peerType))
        }
    }

    @Test
    fun `an unknown config keeps the choice`() {
        // Before the tunnels load, or with no TURN config at all: as before.
        assertTrue(ConnectionMode.isOffered(null))
    }
}
