/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

/**
 * VK call links as the user types them and as the native side wants them.
 *
 * The join hash is what the proxy actually uses (`https://vk.ru/call/join/<hash>`
 * is rebuilt around it), and the reduction here mirrors joinHash in libwg-go so
 * a link the screen accepts is exactly the string the start will join with.
 */
object VkLinks {
    /** As many links as wgTurnProxyStart reads (parseLinks caps at eight). */
    const val MAX = 8

    /**
     * The shape of a join hash. Wide on purpose — VK's hashes are opaque, and a
     * check that is too strict would refuse a live call; the check against VK
     * itself is what tells a working link from a broken one.
     */
    private val HASH = Regex("^[A-Za-z0-9_-]{6,128}$")

    /** The join hash of one link or bare hash, or null when the text is neither. */
    fun hash(raw: String): String? {
        val text = raw.trim()
        if (text.isEmpty()) return null
        val afterJoin = if ("join/" in text) text.substringAfterLast("join/") else text
        val hash = afterJoin.takeWhile { it !in "/?#" }
        return hash.takeIf { HASH.matches(it) }
    }

    /**
     * What the field holds: the hashes in order, without repeats and capped at
     * [MAX]; the entries that are not links, for the screen to point at; and
     * whether anything was cut by the cap.
     */
    data class Parsed(val hashes: List<String>, val invalid: List<String>, val truncated: Boolean)

    /** Entries are separated by line breaks, commas, pipes or whitespace. */
    fun parse(text: String): Parsed {
        val hashes = ArrayList<String>()
        val invalid = ArrayList<String>()
        for (entry in text.split(SEPARATORS)) {
            if (entry.isEmpty()) continue
            val hash = hash(entry)
            when {
                hash == null -> invalid.add(entry)
                hash !in hashes -> hashes.add(hash)
            }
        }
        return Parsed(hashes.take(MAX), invalid, hashes.size > MAX)
    }

    /** A config's VKLink value split the way the native side splits it. */
    fun split(vkLink: String): List<String> =
        vkLink.split(',', '|').map { it.trim() }.filter { it.isNotEmpty() }

    private val SEPARATORS = Regex("[\\n\\r,|\\s]+")
}
