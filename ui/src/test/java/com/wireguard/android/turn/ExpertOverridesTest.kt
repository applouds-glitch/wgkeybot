/* SPDX-License-Identifier: Apache-2.0 */

package com.wireguard.android.turn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ExpertOverridesTest {
    @Test
    fun `the MTU range has the documented bounds`() {
        assertTrue(ExpertOverrides.isValidMtu(1000))
        assertTrue(ExpertOverrides.isValidMtu(1500))
        assertFalse(ExpertOverrides.isValidMtu(999))
        assertFalse(ExpertOverrides.isValidMtu(1501))
        assertFalse(ExpertOverrides.isValidMtu(0))
    }

    @Test
    fun `resolvers parse as a comma separated list of addresses`() {
        val parsed = ExpertOverrides.parseDns(" 1.1.1.1, 2606:4700:4700::1111 ,8.8.8.8 ")!!
        // IPv6 text is not compared: the JVM spells it out in full where
        // Android compresses it, and the address is what matters.
        assertEquals(3, parsed.size)
        assertEquals("1.1.1.1", parsed[0].hostAddress)
        assertTrue(parsed[1] is java.net.Inet6Address)
        assertEquals("8.8.8.8", parsed[2].hostAddress)
        assertEquals("1.1.1.1, 8.8.8.8", ExpertOverrides.formatDns(listOf(parsed[0], parsed[2])))
    }

    @Test
    fun `blank resolver text is an empty list, not an error`() {
        assertEquals(emptyList<Any>(), ExpertOverrides.parseDns(""))
        assertEquals(emptyList<Any>(), ExpertOverrides.parseDns(" , "))
    }

    @Test
    fun `a name or a broken address refuses the whole list`() {
        assertNull(ExpertOverrides.parseDns("dns.google"))
        assertNull(ExpertOverrides.parseDns("1.1.1.1, 300.1.1.1"))
        assertNull(ExpertOverrides.parseDns("1.1.1.1:53"))
    }

    @Test
    fun `nothing set is empty`() {
        assertTrue(ExpertOverrides.NONE.isEmpty)
        assertFalse(ExpertOverrides(mtu = 1200).isEmpty)
        assertFalse(ExpertOverrides(dns = ExpertOverrides.parseDns("1.1.1.1")).isEmpty)
    }
}
