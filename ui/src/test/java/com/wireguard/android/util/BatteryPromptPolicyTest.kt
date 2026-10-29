/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import com.wireguard.android.fragment.TunnelState
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BatteryPromptPolicyTest {
    @Test
    fun `the first connected session offers the exemption`() {
        assertTrue(BatteryPromptPolicy.shouldOffer(TunnelState.Connected, alreadyShown = false, exempt = false))
    }

    /** Import, the split wizard and the VPN consent all happen before Connected. */
    @Test
    fun `nothing short of connected offers it`() {
        for (state in TunnelState.entries - TunnelState.Connected) {
            assertFalse(state.name, BatteryPromptPolicy.shouldOffer(state, alreadyShown = false, exempt = false))
        }
    }

    @Test
    fun `it is offered once, whatever the answer was`() {
        assertFalse(BatteryPromptPolicy.shouldOffer(TunnelState.Connected, alreadyShown = true, exempt = false))
    }

    @Test
    fun `an app that is already exempt is not asked`() {
        assertFalse(BatteryPromptPolicy.shouldOffer(TunnelState.Connected, alreadyShown = false, exempt = true))
    }
}
