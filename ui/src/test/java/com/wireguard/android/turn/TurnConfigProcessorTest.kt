/* SPDX-License-Identifier: Apache-2.0 */

package com.wireguard.android.turn

import com.wireguard.config.Config
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.io.ByteArrayInputStream

class TurnConfigProcessorTest {
    private fun configWithKeepalive(seconds: Int): Config {
        val text = """
            [Interface]
            Address = 192.0.2.2/32
            PrivateKey = TFlmmEUC7V7VtiDYLKsbP5rySTKLIZq1yn8lMqK83wo=

            [Peer]
            AllowedIPs = 0.0.0.0/0
            Endpoint = 192.0.2.1:51820
            PersistentKeepalive = $seconds
            PublicKey = vBN7qyUTb5lJtWYJ8LhbPio1Z4RcyBPGnqFBGn6O6Qg=
        """.trimIndent()
        return Config.parse(ByteArrayInputStream(text.toByteArray()))
    }

    @Test
    fun `DTLS TURN mode disables independent WireGuard keepalive timer`() {
        val modified = TurnConfigProcessor.modifyConfigForActiveTurn(
            configWithKeepalive(10),
            TurnSettings(peerType = "proxy_v2", localPort = 9000),
        )

        assertFalse(modified.peers.single().persistentKeepalive.isPresent)
        assertEquals(9000, modified.peers.single().endpoint.orElseThrow().port)
    }

    @Test
    fun `raw WireGuard over TURN also disables independent keepalive timer`() {
        val modified = TurnConfigProcessor.modifyConfigForActiveTurn(
            configWithKeepalive(10),
            TurnSettings(peerType = "wireguard", localPort = 9000),
        )

        assertFalse(modified.peers.single().persistentKeepalive.isPresent)
    }
}
