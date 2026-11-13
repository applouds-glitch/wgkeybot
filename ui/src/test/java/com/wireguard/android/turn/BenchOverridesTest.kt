/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.turn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BenchOverridesTest {
    @Test
    fun `every key is read and trimmed`() {
        val o = BenchOverrides.parse(listOf("extra = 95.163.34.160, 95.163.34.48", "turnip=1.2.3.4", "streams=20 ", " spc=10"))
        assertEquals("95.163.34.160, 95.163.34.48", o.extraRelays)
        assertEquals("1.2.3.4", o.turnIp)
        assertEquals(20, o.streams)
        assertEquals(10, o.streamsPerCred)
    }

    @Test
    fun `absent keys keep the config, junk is ignored`() {
        val o = BenchOverrides.parse(listOf("# comment", "streams", "extra=", "foo=bar", "streams=abc", "spc=99"))
        assertEquals("", o.extraRelays) // an empty value is a value: no extras for this start
        assertNull(o.turnIp)
        assertNull(o.streams)
        assertNull(o.streamsPerCred) // above MAX_STREAMS_PER_CREDENTIAL
    }

    @Test
    fun `peer is taken only as host and port`() {
        assertEquals("203.0.113.10:56004", BenchOverrides.parse(listOf("peer = 203.0.113.10:56004")).peer)
        for (bad in listOf("peer=203.0.113.10", "peer=", "peer=host:port", "peer=a b:1")) {
            assertNull(bad, BenchOverrides.parse(listOf(bad)).peer)
        }
        assertTrue(!BenchOverrides.parse(listOf("peer=h:1")).isEmpty)
    }

    @Test
    fun `no lines means nothing to override`() {
        assertTrue(BenchOverrides.parse(emptyList()).isEmpty)
    }
}
