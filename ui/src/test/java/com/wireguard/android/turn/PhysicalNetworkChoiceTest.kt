/* SPDX-License-Identifier: Apache-2.0 */

package com.wireguard.android.turn

import com.wireguard.android.turn.PhysicalNetworkChoice.Candidate
import com.wireguard.android.turn.PhysicalNetworkChoice.Transport.CELLULAR
import com.wireguard.android.turn.PhysicalNetworkChoice.Transport.OTHER
import com.wireguard.android.turn.PhysicalNetworkChoice.Transport.WIFI
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PhysicalNetworkChoiceTest {
    private fun wifi(validated: Boolean) = Candidate("wifi", WIFI, validated)
    private fun cell(validated: Boolean) = Candidate("cell", CELLULAR, validated)

    @Test
    fun `no network is no choice`() {
        assertNull(PhysicalNetworkChoice.pick(emptyList<Candidate<String>>(), current = "cell"))
    }

    @Test
    fun `the only network is the choice, validated or not`() {
        // Behind a whitelist the cellular network never validates; it is still
        // the network the relays answer on.
        assertEquals("cell", PhysicalNetworkChoice.pick(listOf(cell(validated = false)), current = null))
    }

    @Test
    fun `validated wifi takes over from cellular`() {
        // The handover the monitor exists for: Wi-Fi with real internet arrives
        // while mobile data stays up.
        val candidates = listOf(cell(validated = true), wifi(validated = true))
        assertEquals("wifi", PhysicalNetworkChoice.pick(candidates, current = "cell"))
    }

    @Test
    fun `validated cellular takes over from wifi that lost its uplink`() {
        val candidates = listOf(wifi(validated = false), cell(validated = true))
        assertEquals("cell", PhysicalNetworkChoice.pick(candidates, current = "wifi"))
    }

    @Test
    fun `cellular that lost validation is not left for wifi that has none`() {
        // The whitelist was switched on mid-session: Google's check stops
        // passing, the relays keep answering. The Wi-Fi next to it has never
        // validated, so there is nothing to say it is any better.
        val candidates = listOf(wifi(validated = false), cell(validated = false))
        assertEquals("cell", PhysicalNetworkChoice.pick(candidates, current = "cell"))
        assertTrue(PhysicalNetworkChoice.keptAgainstTransportOrder(candidates, current = "cell"))
    }

    @Test
    fun `wifi that has not validated yet does not pull the sessions over`() {
        // Validation takes a second or two after a Wi-Fi connects. Until it
        // passes — and for a captive portal it never does — stay put.
        val arriving = listOf(cell(validated = false), wifi(validated = false))
        assertEquals("cell", PhysicalNetworkChoice.pick(arriving, current = "cell"))

        val validatedNow = listOf(cell(validated = false), wifi(validated = true))
        assertEquals("wifi", PhysicalNetworkChoice.pick(validatedNow, current = "cell"))
    }

    @Test
    fun `a current network that is gone is not kept`() {
        val candidates = listOf(wifi(validated = false))
        assertEquals("wifi", PhysicalNetworkChoice.pick(candidates, current = "cell"))
        assertFalse(PhysicalNetworkChoice.keptAgainstTransportOrder(candidates, current = "cell"))
    }

    @Test
    fun `with nothing validated and nothing in use, wifi comes before cellular`() {
        val candidates = listOf(cell(validated = false), Candidate("eth", OTHER, false), wifi(validated = false))
        assertEquals("wifi", PhysicalNetworkChoice.pick(candidates, current = null))
        assertEquals("cell", PhysicalNetworkChoice.pick(candidates - wifi(validated = false), current = null))
    }

    @Test
    fun `staying on the network the transport order would pick anyway is not worth a log line`() {
        val candidates = listOf(wifi(validated = false), cell(validated = false))
        assertFalse(PhysicalNetworkChoice.keptAgainstTransportOrder(candidates, current = "wifi"))
        // Nor is a choice that validation made.
        val validated = listOf(wifi(validated = false), cell(validated = true))
        assertFalse(PhysicalNetworkChoice.keptAgainstTransportOrder(validated, current = "cell"))
    }
}
