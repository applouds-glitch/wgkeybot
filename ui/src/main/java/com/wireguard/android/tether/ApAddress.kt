/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.tether

/**
 * Picks the address the sharing proxy should listen on, given the private IPv4
 * addresses present before the access point was raised and after.
 *
 * The identifying property of the access point is neither its interface name nor
 * its subnet. Vendors name it wlan1, ap0, swlan0 — and, as one device proved,
 * wlan2 — while Android randomises the local-only hotspot subnet, so it need not
 * be 192.168.x at all. What is reliably true is that its address was not there a
 * moment ago. Everything else on the device — station Wi-Fi, the app's own tunnel,
 * mobile data — was.
 *
 * Kept free of Android types so it can be tested on the JVM; the caller does the
 * enumerating and the filtering.
 *
 * @param before interface name to its private IPv4 addresses, sampled before the request
 * @param after the same, sampled after the hotspot reported itself started
 * @param hints interface-name prefixes that look like a soft AP, used only to break ties
 * @return the address to bind, or null when nothing identifies the access point
 */
internal fun pickApAddress(
    before: Map<String, Set<String>>,
    after: Map<String, Set<String>>,
    hints: List<String>,
): String? {
    val appeared = after.mapNotNull { (iface, addresses) ->
        val fresh = addresses - before[iface].orEmpty()
        if (fresh.isEmpty()) null else iface to fresh
    }

    // Exactly one interface gained an address: that is the access point, and its
    // name does not matter.
    appeared.singleOrNull()?.let { (_, fresh) -> return fresh.first() }

    // Several gained one — mobile data reconnecting in the same window, say. Now
    // the name earns its keep as a tie-breaker.
    appeared.firstOrNull { (iface, _) -> hints.any { iface.startsWith(it) } }
        ?.let { (_, fresh) -> return fresh.first() }

    // Nothing appeared: the interface may have carried its address over from a
    // previous run. The name is all that is left to go on.
    after.entries
        .firstOrNull { (iface, addresses) -> addresses.isNotEmpty() && hints.any { iface.startsWith(it) } }
        ?.let { return it.value.first() }

    // Several appeared and none looks like an access point. Guessing loses: a wrong
    // address reaches the user as an opaque bind failure, so let the caller say
    // what it saw instead.
    return null
}
