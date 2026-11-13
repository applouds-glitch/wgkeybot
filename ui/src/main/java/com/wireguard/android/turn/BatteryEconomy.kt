/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context

/**
 * The battery economy of an idle tunnel: with the screen off, the native layer
 * sends its keepalives every 50 s instead of 25 (keepalive_economy.go).
 *
 * What an idle tunnel costs on a cellular network is the radio, which every
 * keepalive burst holds up for the modem's tail of 5-10 s. Night of 2026-11-12
 * (Pixel 6a, LTE, relays over TCP, screen off): 74% of the battery in 9h47m,
 * the modem receiving 72% of the time.
 *
 * This side only says when: the setting is on and the screen is off. Whether
 * the grid goes wide for it is the native layer's — only while the relays are
 * reached over TCP, where a mobile NAT keeps an idle flow for minutes; over UDP
 * it forgets one in tens of seconds, and the 25 s stay.
 *
 * On by default. The cost is that a relay gone quiet under an idle tunnel is
 * found in 150 s instead of 90, with the screen off; the switch is there for a
 * network where 50 s between keepalives turns out to be too long.
 */
object BatteryEconomy {
    private const val PREFS = "turn_mode"
    private const val KEY = "battery_economy"

    fun isEnabled(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY, true)

    fun setEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(KEY, enabled).apply()
    }

    /**
     * What the native layer is told. The screen, not the lock: a screen that is
     * on has the radio up for whatever lit it, and a relay gone quiet should
     * then be found at the usual pace.
     */
    fun asks(enabled: Boolean, screenOn: Boolean): Boolean = enabled && !screenOn
}
