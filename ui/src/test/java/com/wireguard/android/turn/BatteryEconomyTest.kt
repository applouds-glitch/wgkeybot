/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BatteryEconomyTest {
    @Test
    fun asksOnlyWithTheScreenOffAndTheSettingOn() {
        assertTrue(BatteryEconomy.asks(enabled = true, screenOn = false))
        assertFalse(BatteryEconomy.asks(enabled = true, screenOn = true))
        assertFalse(BatteryEconomy.asks(enabled = false, screenOn = false))
        assertFalse(BatteryEconomy.asks(enabled = false, screenOn = true))
    }
}
