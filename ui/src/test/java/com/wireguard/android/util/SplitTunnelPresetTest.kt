/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SplitTunnelPresetTest {
    @Test
    fun `only the bypass mode starts with a selection`() {
        assertEquals(SplitTunnelPreset.BYPASS, SplitTunnelPreset.forWizard(excluded = true))
        assertTrue(SplitTunnelPreset.forWizard(excluded = false).isEmpty())
    }

    @Test
    fun `the list holds package names, each once`() {
        val name = Regex("""[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+""")
        for (pkg in SplitTunnelPreset.BYPASS) assertTrue(pkg, name.matches(pkg))
        assertEquals(SplitTunnelPreset.BYPASS.size, SplitTunnelPreset.BYPASS.toSet().size)
    }

    /** Excluded, the app's own config refresh would go around the tunnel it is for. */
    @Test
    fun `the app itself is never in it`() {
        assertFalse(SplitTunnelPreset.BYPASS.any { it.startsWith("com.wgkeybot.") })
    }
}
