/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.tether

import android.content.Context

/**
 * The one preference sharing has of its own.
 *
 * Plain SharedPreferences rather than the app's DataStore because the reader is
 * [TetherManager]'s stats tick: it runs on the main thread every couple of
 * seconds and needs an answer synchronously. After the first load these reads
 * are an in-memory map lookup, which is the same trade ConnectionMode makes.
 */
object TetherSettings {
    private const val PREFS = "tether"
    private const val KEY_AUTO_OFF = "auto_off_when_idle"

    /**
     * Whether an idle session switches itself off (see TetherManager's
     * AUTO_OFF_IDLE_MS).
     *
     * On by default, and that is the whole point of the feature: the user who
     * leaves a hotspot running overnight is by definition not the user who would
     * have gone into settings to arm the timer. The switch exists for the
     * opposite case — "I know nothing will connect for an hour, leave it alone".
     */
    fun isAutoOffEnabled(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_AUTO_OFF, true)

    fun setAutoOffEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean(KEY_AUTO_OFF, enabled).apply()
    }
}
