/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.turn

/**
 * The stream counts a TURN start tries, in order: the config's count, then its
 * fallback (`FallbackStreamNum`) when it names another one.
 *
 * Nothing carries over from the start before. The count a start came up with
 * used to be remembered and tried first on every later start short of a
 * disconnect by the user, the watchdog's rebuild under the live tunnel
 * included. A start that came up on the fallback then kept every rebuild at
 * the fallback's count — 6 streams, a ceiling of about 11 Mbit/s against 17 at
 * 10 — for as long as the tunnel stayed up. A start fails because no stream
 * proved the path within its 30 s (the network, DNS to VK, VK itself), which
 * the count does not change: in the field log of 2026-10-08 the 6 streams
 * failed right after the 8 twice and came up once, in that second 30 s window.
 * The local field logs hold no rebuild that came up on a remembered fallback —
 * every "(remembered)" start there ran the config's 8, the label only saying a
 * count had been stored — so this closes a path, it does not answer a case seen.
 */
object StreamCounts {
    fun toTry(primary: Int, fallback: Int): List<Int> =
        if (fallback > 0 && fallback != primary) listOf(primary, fallback) else listOf(primary)
}
