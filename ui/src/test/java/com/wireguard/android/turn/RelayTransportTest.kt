/* SPDX-License-Identifier: Apache-2.0 */

package com.wireguard.android.turn

import com.wireguard.android.backend.TurnBackend
import com.wireguard.android.turn.RelayTransport.Mode
import com.wireguard.android.turn.RelayTransport.Operator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayTransportTest {
    private val rtk = Operator(listOf("ROSTELECOM"))
    private val tele2 = Operator(listOf("Tele2", "Tele2"))

    private fun wire(mode: Mode, onCellular: Boolean, operator: Operator) =
        RelayTransport.choose(mode, onCellular, operator).wire

    @Test
    fun `auto leaves an ordinary network to the config`() {
        assertEquals(TurnBackend.RELAY_TRANSPORT_AS_CONFIGURED, wire(Mode.AUTO, onCellular = true, operator = tele2))
        assertEquals(TurnBackend.RELAY_TRANSPORT_AS_CONFIGURED, wire(Mode.AUTO, onCellular = false, operator = Operator.NONE))
    }

    @Test
    fun `auto picks TCP on the Rostelecom mobile network`() {
        // The first dial has to go the right way: a failed attempt there was
        // reported to cost minutes of blocked DNS.
        assertEquals(TurnBackend.RELAY_TRANSPORT_TCP, wire(Mode.AUTO, onCellular = true, operator = rtk))
    }

    @Test
    fun `a Rostelecom SIM says nothing about the wifi the tunnel runs over`() {
        assertEquals(TurnBackend.RELAY_TRANSPORT_AS_CONFIGURED, wire(Mode.AUTO, onCellular = false, operator = rtk))
    }

    @Test
    fun `settings overrule the operator both ways`() {
        // UDP for an RTK SIM on a network that is not whitelisted…
        assertEquals(TurnBackend.RELAY_TRANSPORT_UDP, wire(Mode.UDP, onCellular = true, operator = rtk))
        // …and TCP for a SIM the rule does not know, or a router carrying one.
        assertEquals(TurnBackend.RELAY_TRANSPORT_TCP, wire(Mode.TCP, onCellular = true, operator = tele2))
        assertEquals(TurnBackend.RELAY_TRANSPORT_TCP, wire(Mode.TCP, onCellular = false, operator = Operator.NONE))
    }

    @Test
    fun `the operator is recognised by name in either script and any case`() {
        assertTrue(RelayTransport.needsTcp(Operator(listOf("ROSTELECOM"))))
        assertTrue(RelayTransport.needsTcp(Operator(listOf("Tele2", "Rostelecom RU"))))
        assertTrue(RelayTransport.needsTcp(Operator(listOf("Ростелеком"))))
    }

    @Test
    fun `other operators and no operator do not need TCP`() {
        assertFalse(RelayTransport.needsTcp(tele2))
        assertFalse(RelayTransport.needsTcp(Operator(listOf("MTS RUS", "Beeline", "MegaFon"))))
        assertFalse(RelayTransport.needsTcp(Operator.NONE))
    }

    @Test
    fun `an unknown stored value is auto`() {
        assertEquals(Mode.AUTO, Mode.fromPref(null))
        assertEquals(Mode.AUTO, Mode.fromPref("quic"))
        assertEquals(Mode.TCP, Mode.fromPref("tcp"))
        assertEquals(Mode.UDP, Mode.fromPref("udp"))
    }

    @Test
    fun `the reason names what decided`() {
        assertTrue(RelayTransport.choose(Mode.AUTO, true, rtk).reason.contains("ROSTELECOM"))
        assertTrue(RelayTransport.choose(Mode.TCP, false, Operator.NONE).reason.contains("settings"))
    }
}
