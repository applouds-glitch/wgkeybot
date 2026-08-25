/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.tether

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ApAddressTest {

    private val hints = listOf("ap", "swlan", "softap", "wlan1")

    /**
     * The case that shipped broken. On a real device the access point came up on
     * `wlan2` — a name no hint list predicted — with 10.226.28.76, because Android
     * randomises the local-only hotspot subnet and it need not be 192.168.x at all.
     * Meanwhile the station Wi-Fi (192.168.1.45) and our own tunnel (10.66.66.17)
     * were already there and are equally private. What tells the access point apart
     * is not its name and not its subnet: it is the address that was not there a
     * moment ago.
     */
    @Test
    fun `picks the address that appeared, whatever the interface is called`() {
        val before = linkedMapOf(
            "wlan0" to setOf("192.168.1.45"),
            "tun0" to setOf("10.66.66.17"),
            "wlan2" to emptySet<String>(),
        )
        val after = linkedMapOf(
            "wlan0" to setOf("192.168.1.45"),
            "tun0" to setOf("10.66.66.17"),
            "wlan2" to setOf("10.226.28.76"),
        )

        assertEquals("10.226.28.76", pickApAddress(before, after, hints))
    }

    /** An interface that did not exist at all before is just as new. */
    @Test
    fun `picks an interface that appeared whole`() {
        val before = linkedMapOf("wlan0" to setOf("192.168.1.45"))
        val after = linkedMapOf(
            "wlan0" to setOf("192.168.1.45"),
            "ap0" to setOf("192.168.43.1"),
        )

        assertEquals("192.168.43.1", pickApAddress(before, after, hints))
    }

    /**
     * If something else gains an address in the same window — mobile data
     * reconnecting, say — the name hints break the tie rather than a coin flip.
     */
    @Test
    fun `prefers a hinted name when several addresses appear`() {
        val before = linkedMapOf("wlan0" to setOf("192.168.1.45"))
        val after = linkedMapOf(
            "wlan0" to setOf("192.168.1.45"),
            "rmnet1" to setOf("10.8.7.6"),
            "swlan0" to setOf("192.168.43.1"),
        )

        assertEquals("192.168.43.1", pickApAddress(before, after, hints))
    }

    /**
     * The access point interface may have carried its address from a previous run,
     * in which case nothing appears and the name is all we have left.
     */
    @Test
    fun `falls back to a hinted name when nothing appeared`() {
        val snapshot = linkedMapOf(
            "wlan0" to setOf("192.168.1.45"),
            "wlan1" to setOf("192.168.43.1"),
        )

        assertEquals("192.168.43.1", pickApAddress(snapshot, snapshot, hints))
    }

    /**
     * Guessing here is worse than failing: a wrong address surfaces as an opaque
     * "cannot assign requested address" from the proxy's bind, which is exactly how
     * this bug reached a user.
     */
    @Test
    fun `returns null rather than guessing when nothing identifies the access point`() {
        val snapshot = linkedMapOf(
            "wlan0" to setOf("192.168.1.45"),
            "tun0" to setOf("10.66.66.17"),
        )

        assertNull(pickApAddress(snapshot, snapshot, hints))
    }
}
