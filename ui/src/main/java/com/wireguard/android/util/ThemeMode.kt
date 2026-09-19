/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import androidx.appcompat.app.AppCompatDelegate

/**
 * Which theme the app wears: the phone's own, or one picked by hand.
 *
 * The stored default is [DARK] and stays so: an install that never opened the
 * settings looks the way it always has, and following the system is something
 * the user turns on. [pref] is what [AuthStore] keeps; "system" has been a
 * value the app start understood long before the settings offered it.
 */
enum class ThemeMode(val pref: String) {
    SYSTEM("system"),
    LIGHT("light"),
    DARK("dark");

    /** The value for [AppCompatDelegate.setDefaultNightMode]. */
    val nightMode: Int
        get() = when (this) {
            SYSTEM -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
            LIGHT -> AppCompatDelegate.MODE_NIGHT_NO
            DARK -> AppCompatDelegate.MODE_NIGHT_YES
        }

    companion object {
        /** Nothing stored, or something no version ever wrote, is the default. */
        fun fromPref(value: String?): ThemeMode = entries.firstOrNull { it.pref == value } ?: DARK
    }
}
