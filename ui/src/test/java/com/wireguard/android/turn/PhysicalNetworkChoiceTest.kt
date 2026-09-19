/* SPDX-License-Identifier: Apache-2.0 */

package com.wireguard.android.turn

import com.wireguard.android.turn.PhysicalNetworkChoice.Candidate
import com.wireguard.android.turn.PhysicalNetworkChoice.SystemPick
import com.wireguard.android.turn.PhysicalNetworkChoice.Transport.CELLULAR
import com.wireguard.android.turn.PhysicalNetworkChoice.Transport.OTHER
import com.wireguard.android.turn.PhysicalNetworkChoice.Transport.WIFI
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PhysicalNetworkChoiceTest {
    private val wifi = Candidate("wifi", WIFI)
    private val cell = Candidate("cell", CELLULAR)
    private val eth = Candidate("eth", OTHER)

    @Test
    fun `android's pick is the answer`() {
        // Cellular behind a whitelist with a dead Wi-Fi next to it, a Wi-Fi the
        // user told Android to use anyway, a captive portal: Android has weighed
        // what we cannot see, and it is the network every other app is on.
        assertEquals("cell", PhysicalNetworkChoice.pick(SystemPick("cell"), listOf(wifi, cell)))
        assertEquals("wifi", PhysicalNetworkChoice.pick(SystemPick("wifi"), listOf(wifi, cell)))
    }

    @Test
    fun `android's pick stands even if we have not seen that network ourselves`() {
        assertEquals("cell", PhysicalNetworkChoice.pick(SystemPick("cell"), emptyList()))
    }

    @Test
    fun `android having no network means no network`() {
        // Whatever is left in our own list is stale by definition: the workers
        // must be parked, not pointed at a network the platform has given up on.
        assertNull(PhysicalNetworkChoice.pick(SystemPick<String>(null), listOf(wifi, cell)))
    }

    @Test
    fun `until android has spoken, wifi comes before cellular before anything else`() {
        // Before API 31, and in the first milliseconds after start.
        assertEquals("wifi", PhysicalNetworkChoice.pick(null, listOf(eth, cell, wifi)))
        assertEquals("cell", PhysicalNetworkChoice.pick(null, listOf(eth, cell)))
        assertEquals("eth", PhysicalNetworkChoice.pick(null, listOf(eth)))
    }

    @Test
    fun `no network is no choice`() {
        assertNull(PhysicalNetworkChoice.pick(null, emptyList<Candidate<String>>()))
    }
}
