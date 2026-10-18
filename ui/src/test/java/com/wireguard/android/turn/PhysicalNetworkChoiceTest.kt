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
    fun `android's pick beats its default network`() {
        assertEquals("wifi", PhysicalNetworkChoice.pick(SystemPick("wifi"), listOf(wifi, cell), systemDefault = "cell"))
    }

    @Test
    fun `a no-network pick yields to a physical default network`() {
        // Field logs 2026-10-09/10: the callback said "no network" while the phone
        // was on cellular. The default network is asked for directly; our own
        // list still is not used.
        assertEquals("cell", PhysicalNetworkChoice.pick(SystemPick<String>(null), listOf(wifi), systemDefault = "cell"))
    }

    @Test
    fun `a fresh no-network pick is believed, even with a default network`() {
        // Field log 2026-10-12 (Xiaomi, cellular reconnecting every 10-15s): for a
        // second or two after the loss, asked directly, Android still names the
        // network it has just lost. The new one came within 2.8s every time.
        assertNull(PhysicalNetworkChoice.pick(SystemPick<String>(null), listOf(wifi), systemDefault = "cell", noneForMs = 0))
        assertNull(PhysicalNetworkChoice.pick(SystemPick<String>(null), listOf(wifi), systemDefault = "cell", noneForMs = 2_800))
        assertNull(PhysicalNetworkChoice.pick(SystemPick<String>(null), listOf(wifi), systemDefault = "cell",
            noneForMs = PhysicalNetworkChoice.STALE_NONE_AFTER_MS - 1))
    }

    @Test
    fun `a no-network pick that has lasted yields to the default network`() {
        // The stale "none" of 2026-10-09/10 lasted minutes.
        assertEquals("cell", PhysicalNetworkChoice.pick(SystemPick<String>(null), listOf(wifi), systemDefault = "cell",
            noneForMs = PhysicalNetworkChoice.STALE_NONE_AFTER_MS))
        assertEquals("cell", PhysicalNetworkChoice.pick(SystemPick<String>(null), emptyList(), systemDefault = "cell",
            noneForMs = 22 * 60_000L))
    }

    @Test
    fun `before android has spoken the default network needs no wait`() {
        // No "none" to distrust: nothing has been lost yet.
        assertEquals("cell", PhysicalNetworkChoice.pick(null, emptyList(), systemDefault = "cell", noneForMs = 0))
    }

    @Test
    fun `no pick and no physical default network is no network`() {
        // Airplane mode: asked directly, Android has no physical network either.
        assertNull(PhysicalNetworkChoice.pick(SystemPick<String>(null), listOf(wifi, cell), systemDefault = null))
    }

    @Test
    fun `before android has spoken the ranking comes first, then the default network`() {
        assertEquals("wifi", PhysicalNetworkChoice.pick(null, listOf(cell, wifi), systemDefault = "cell"))
        assertEquals("cell", PhysicalNetworkChoice.pick(null, emptyList(), systemDefault = "cell"))
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

    // ── bindOrder: where the captcha WebView goes ──────────────────────────────

    @Test
    fun `the captcha goes out over the network turn is on`() {
        // Cellular carries the tunnel while a Wi-Fi is up next to it: the platform
        // lists them in no particular order, and the first one used to win.
        assertEquals(listOf("cell", "wifi"), PhysicalNetworkChoice.bindOrder("cell", listOf(wifi, cell)))
    }

    @Test
    fun `the rest follow by transport, for when binding is refused`() {
        assertEquals(listOf("eth", "wifi", "cell"), PhysicalNetworkChoice.bindOrder("eth", listOf(cell, eth, wifi)))
    }

    @Test
    fun `the network in use leads even if we have not listed it ourselves`() {
        assertEquals(listOf("cell", "wifi"), PhysicalNetworkChoice.bindOrder("cell", listOf(wifi)))
    }

    @Test
    fun `with no network in use the order is by transport`() {
        assertEquals(listOf("wifi", "cell", "eth"), PhysicalNetworkChoice.bindOrder(null, listOf(eth, cell, wifi)))
        assertEquals(emptyList<String>(), PhysicalNetworkChoice.bindOrder(null, emptyList<Candidate<String>>()))
    }
}
