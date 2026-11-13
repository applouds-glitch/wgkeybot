/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.turn

import org.junit.Assert.assertEquals
import org.junit.Test

class StreamCountsTest {
    @Test
    fun `the config's count first, then its fallback`() {
        assertEquals(listOf(10, 6), StreamCounts.toTry(primary = 10, fallback = 6))
    }

    @Test
    fun `no fallback when none is set or it names the same count`() {
        assertEquals(listOf(10), StreamCounts.toTry(primary = 10, fallback = 0))
        assertEquals(listOf(10), StreamCounts.toTry(primary = 10, fallback = -1))
        assertEquals(listOf(10), StreamCounts.toTry(primary = 10, fallback = 10))
    }

    @Test
    fun `a fallback above the config's count is still tried after it`() {
        assertEquals(listOf(4, 8), StreamCounts.toTry(primary = 4, fallback = 8))
    }
}
