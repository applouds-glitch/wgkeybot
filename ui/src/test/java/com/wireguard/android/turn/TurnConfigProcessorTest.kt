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

    private fun configWithMtu(mtu: Int?): Config {
        val mtuLine = mtu?.let { "MTU = $it" } ?: ""
        val text = """
            [Interface]
            Address = 192.0.2.2/32
            PrivateKey = TFlmmEUC7V7VtiDYLKsbP5rySTKLIZq1yn8lMqK83wo=
            $mtuLine

            [Peer]
            AllowedIPs = 0.0.0.0/0
            Endpoint = 192.0.2.1:51820
            PublicKey = vBN7qyUTb5lJtWYJ8LhbPio1Z4RcyBPGnqFBGn6O6Qg=
        """.trimIndent()
        return Config.parse(ByteArrayInputStream(text.toByteArray()))
    }

    private fun turnMtu(config: Config): Int =
        TurnConfigProcessor.modifyConfigForActiveTurn(config, TurnSettings(peerType = "wireguard", localPort = 9000))
            .`interface`.mtu.orElseThrow()

    @Test
    fun `the MTU the bot issues is kept for TURN`() {
        assertEquals(1280, turnMtu(configWithMtu(1280)))
    }

    @Test
    fun `a config without an MTU gets the TURN default`() {
        assertEquals(TurnConfigProcessor.TURN_DEFAULT_MTU, turnMtu(configWithMtu(null)))
    }

    @Test
    fun `a smaller MTU is kept`() {
        assertEquals(1100, turnMtu(configWithMtu(1100)))
    }

    private fun configWithDns(dns: String): Config {
        val text = """
            [Interface]
            Address = 192.0.2.2/32
            DNS = $dns
            MTU = 1280
            PrivateKey = TFlmmEUC7V7VtiDYLKsbP5rySTKLIZq1yn8lMqK83wo=

            [Peer]
            AllowedIPs = 0.0.0.0/0
            Endpoint = 192.0.2.1:51820
            PublicKey = vBN7qyUTb5lJtWYJ8LhbPio1Z4RcyBPGnqFBGn6O6Qg=
        """.trimIndent()
        return Config.parse(ByteArrayInputStream(text.toByteArray()))
    }

    private val settings = TurnSettings(peerType = "proxy_v2", localPort = 9000)

    @Test
    fun `an expert MTU replaces the config's for this start`() {
        val modified = TurnConfigProcessor.modifyConfigForActiveTurn(configWithMtu(1280), settings, ExpertOverrides(mtu = 1200))
        assertEquals(1200, modified.`interface`.mtu.orElseThrow())
    }

    @Test
    fun `an expert MTU also replaces the TURN default`() {
        val modified = TurnConfigProcessor.modifyConfigForActiveTurn(configWithMtu(null), settings, ExpertOverrides(mtu = 1400))
        assertEquals(1400, modified.`interface`.mtu.orElseThrow())
    }

    @Test
    fun `expert resolvers replace the config's rather than join them`() {
        val override = ExpertOverrides(dns = ExpertOverrides.parseDns("1.1.1.1, 1.0.0.1"))
        val modified = TurnConfigProcessor.modifyConfigForActiveTurn(configWithDns("8.8.8.8, 8.8.4.4"), settings, override)
        assertEquals(listOf("1.1.1.1", "1.0.0.1"), modified.`interface`.dnsServers.map { it.hostAddress })
        // The MTU was not part of the override, so the config's stands.
        assertEquals(1280, modified.`interface`.mtu.orElseThrow())
    }

    @Test
    fun `no overrides leaves the config's resolvers and MTU alone`() {
        val modified = TurnConfigProcessor.modifyConfigForActiveTurn(configWithDns("8.8.8.8, 8.8.4.4"), settings, ExpertOverrides.NONE)
        assertEquals(listOf("8.8.8.8", "8.8.4.4"), modified.`interface`.dnsServers.map { it.hostAddress })
        assertEquals(1280, modified.`interface`.mtu.orElseThrow())
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
