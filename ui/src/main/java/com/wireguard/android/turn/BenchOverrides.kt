/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.turn

/**
 * Debug-build overrides for one proxy start, read from `files/ab.txt`.
 *
 * WHY. The phone's A/B benches (info/bench, 2026-10-21 onwards) compare relay
 * layouts and stream counts, and the app has no tunnel editor to set them: the
 * bot reissues the config, and TunnelDetailFragment is unreachable. Every bench
 * so far patched [TurnProxyManager] by hand and reverted it after; from
 * 2026-11-07 the bench copy (`.abtest`) is the only build this Mac can install
 * beside the user's app, so the hook stays, in debug builds only — a release
 * never reads the file. Written over adb with `run-as <pkg> sh -c 'cat >
 * files/ab.txt'`, deleted the same way; a missing file changes nothing.
 *
 * Lines are `key=value`; unknown keys and malformed lines are ignored, a key
 * absent keeps the config's value:
 *  - `extra`   — ExtraRelays, as the config line holds them (`IP[:port], …`)
 *  - `turnip`  — TurnIP pin
 *  - `streams` — stream count for this start
 *  - `spc`     — StreamsPerCred
 *  - `peer`    — the proxy server (`host:port`) for this start: a second server
 *                build on a spare port of the same host, beside production
 *                (2026-11-12: a test build of the server ran on a spare port
 *                while the production port kept serving users)
 */
data class BenchOverrides(
    val extraRelays: String? = null,
    val turnIp: String? = null,
    val streams: Int? = null,
    val streamsPerCred: Int? = null,
    val peer: String? = null,
) {
    val isEmpty: Boolean
        get() = extraRelays == null && turnIp == null && streams == null && streamsPerCred == null && peer == null

    companion object {
        const val FILE_NAME = "ab.txt"
        private val PEER = Regex("^[^\\s:]+:\\d{1,5}$")

        fun parse(lines: List<String>): BenchOverrides {
            val map = lines.mapNotNull { line ->
                val parts = line.split('=', limit = 2)
                if (parts.size != 2) null else parts[0].trim() to parts[1].trim()
            }.toMap()
            return BenchOverrides(
                extraRelays = map["extra"],
                turnIp = map["turnip"],
                streams = map["streams"]?.toIntOrNull()?.takeIf { it in 1..128 },
                streamsPerCred = map["spc"]?.toIntOrNull()?.takeIf { it in 1..TurnSettings.MAX_STREAMS_PER_CREDENTIAL },
                // host:port with a port; anything else would only fail the start.
                peer = map["peer"]?.takeIf { PEER.matches(it) },
            )
        }
    }
}
