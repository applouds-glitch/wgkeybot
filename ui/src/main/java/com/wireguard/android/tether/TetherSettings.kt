/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.tether

import android.content.Context

/**
 * The preferences sharing has of its own.
 *
 * Plain SharedPreferences rather than the app's DataStore because the reader is
 * [TetherManager]'s stats tick: it runs on the main thread every couple of
 * seconds and needs an answer synchronously. After the first load these reads
 * are an in-memory map lookup, which is the same trade ConnectionMode makes.
 */
object TetherSettings {
    private const val PREFS = "tether"
    private const val KEY_AUTO_OFF = "auto_off_when_idle"
    private const val KEY_ROUTING = "split_routing"
    private const val KEY_ROUTING_PROFILE_URL = "routing_profile_url"
    private const val KEY_ROUTING_DIRECT_DNS = "routing_direct_dns"

    /**
     * The routing profile split routing follows: RoscomVPN's whitelist, a Happ
     * profile that sends Russian sites and services past the tunnel and refuses
     * ad, tracking and torrent hosts. See TetherRouting for what is fetched
     * from it.
     */
    const val DEFAULT_ROUTING_PROFILE_URL =
        "https://raw.githubusercontent.com/hydraponique/roscomvpn-routing/refs/heads/main/HAPP/WHITELIST.JSON"

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

    /**
     * Whether tethered clients get split routing from the profile at
     * [routingProfileUrl] instead of everything through the tunnel.
     *
     * Off by default, and that is not caution for its own sake: the sharing
     * sheet's whole pitch is that nothing a client does can leave outside the
     * tunnel, and this is the one switch that makes that untrue. Whoever turns
     * it on has read the row that says so. The settings screen fetches the rules
     * as soon as it is switched on and applies the change to a running session
     * (TetherManager.reloadRouting); a start reads the switch afresh.
     */
    fun isRoutingEnabled(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_ROUTING, false)

    fun setRoutingEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean(KEY_ROUTING, enabled).apply()
    }

    /** Where the routing profile is fetched from; the routing settings screen edits it. */
    fun routingProfileUrl(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_ROUTING_PROFILE_URL, null)?.takeIf { it.isNotBlank() } ?: DEFAULT_ROUTING_PROFILE_URL

    /**
     * Stores a new profile address. Blank restores the default.
     *
     * The cached files are left alone deliberately. [TetherRouting] keys them by
     * the address they came from, so a new address already reads as "nothing
     * cached" and is re-fetched at once; deleting them here would instead be
     * disk work on the tap, and would race a download that is still in flight.
     */
    fun setRoutingProfileUrl(context: Context, url: String) {
        val next = url.trim().ifEmpty { DEFAULT_ROUTING_PROFILE_URL }
        if (next == routingProfileUrl(context)) return
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(KEY_ROUTING_PROFILE_URL, next).apply()
    }

    /**
     * The user's own resolver for names the profile routes direct, comma
     * separated, or empty for the profile's DomesticDns. Handed to the native
     * side as is; see TurnBackend.wgTetherStart.
     */
    fun routingDirectDns(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_ROUTING_DIRECT_DNS, "").orEmpty()

    fun setRoutingDirectDns(context: Context, servers: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(KEY_ROUTING_DIRECT_DNS, servers.trim()).apply()
    }
}
