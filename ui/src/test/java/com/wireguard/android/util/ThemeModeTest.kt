/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import androidx.appcompat.app.AppCompatDelegate
import org.junit.Assert.assertEquals
import org.junit.Test

class ThemeModeTest {
    @Test
    fun `an install that never chose a theme stays dark`() {
        assertEquals(ThemeMode.DARK, ThemeMode.fromPref(null))
        assertEquals(ThemeMode.DARK, ThemeMode.fromPref("sepia"))
    }

    @Test
    fun `every mode survives the round trip through the store`() {
        for (mode in ThemeMode.entries) assertEquals(mode, ThemeMode.fromPref(mode.pref))
    }

    /** The stored words are read by installs already in the field; they cannot change. */
    @Test
    fun `the stored words are the ones older builds wrote`() {
        assertEquals("system", ThemeMode.SYSTEM.pref)
        assertEquals("light", ThemeMode.LIGHT.pref)
        assertEquals("dark", ThemeMode.DARK.pref)
    }

    @Test
    fun `each mode asks AppCompat for its own night mode`() {
        assertEquals(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM, ThemeMode.SYSTEM.nightMode)
        assertEquals(AppCompatDelegate.MODE_NIGHT_NO, ThemeMode.LIGHT.nightMode)
        assertEquals(AppCompatDelegate.MODE_NIGHT_YES, ThemeMode.DARK.nightMode)
    }
}
